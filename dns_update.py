#!/usr/bin/env python3
'''
Client for IPv4 Dynamic DNS updates; see
(https://en.wikipedia.org/wiki/Dynamic_DNS).
Supports EasyDNS, Google, Hurricane Electric's Tunnelbroker.net, and various
other providers.

This program requires Python 3.7.
'''

# Since this program used to be used with Python 2, we both check the version
# trap missing imports (which indicate the version of Python is too old).
try:
  import sys

  if sys.version_info.major < 3:
    print('\nVersion of Python is too old. Program requires version 3.7. '
          f'\nCurrent version is {sys.version}')
    sys.exit(100)

  import argparse
  import base64
  import http
  import http.client
  from http import HTTPStatus
  import logging
  import logging.handlers
  import os.path
  import pickle
  import re
  import socket
  import time
  import urllib
  import urllib.parse
  import urllib.request
except (ImportError, AttributeError) as ex:

  print('\nVersion of Python is too old to determine version. '
        'Program requires version 3.'
        '\nCurrent version is {}'.format(sys.version))
  sys.exit(101)

# NOTE    NOTE    NOTE
# In broad terms, this source is in three parts, which would normally be three
# or more files:
#
# - utility routines
# - configuration routines
# - processing routines
#
# However, as a goal of this program was to allow installing bare on a new
# system without the use of an external installer, all the routines are in
# this single source file.

__author__ = 'Kendra Electronic Wonderworks (uupc-help@kew.com)'
__version__ = '1.0.5'
__copyright__ = (f'Version {__version__}.\n'
                 f'Copyright 2016-2024 by {__author__}.\n'
                 'All commercial rights reserved.\n'
                )

_USER_AGENT = (f'{os.path.basename(__file__)} '
               f'by {__author__} version {__version__}')

_LOGGER = logging.getLogger(__file__)

_PASSWORD_MANAGER = urllib.request.HTTPPasswordMgrWithDefaultRealm()

_ADDRESS_RE = re.compile(r'({octet}\.{octet}\.{octet}\.{octet})'.format(
    octet=r'(25[0-5]|2[0-4]\d|[01]?\d{1,2})'))

# Begin command options and associated data.

# Provider Server side flags
_PASSWORD_FLAG = 'password'
_USERNAME_FLAG = 'username'
_LOG_LEVEL_FLAG = 'log_level'
_PROVIDER_NAME_FLAG = 'provider'
_UPDATE_URL_FLAG = 'update_url'
_QUERY_URL_FLAG = 'query_url'

# Client flags
_TLD_FLAG = 'tld'
_HOSTNAME_FLAG = 'hostname'
_MYIP_FLAG = 'myip'
_BACK_MX_FLAG = 'backmx'
_MX_FLAG = 'mx'
_WILDCARD_FLAG = 'wildcard'
_OFFLINE_FLAG = 'offline'
_CACHE_PROVIDER_ADDRESS_SECONDS = 'cache_provider_address_seconds'
_CHECK_PROVIDER_ADDRESS = 'check_provider_address'

# Flags used by program itself.
_CONFIGURATION_FILE_FLAG = 'from'
_SAVE_FILE_FLAG = 'save'
_POLL_INTERVAL_SECONDS_FLAG = 'poll_interval_seconds'

# Not a flag, but stored as part the in-memory copy of configuration map to
# cache it
_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS = '_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS'

# Providers
_SIMPLE = 'simple'
_EXTENDED = 'extended'
_GOOGLE = 'google'
_EASYDNS = 'easydns'
_TUNNEL_BROKER = 'tunnelbroker'

_COMMAND_PREFIX = '--'
_NO_PREFIX = 'no_'

_LOG_LEVELS = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
    }

class Provider():
  '''Holder for provider specific metadata.'''
  generic_optional_flags = (
      _WILDCARD_FLAG,
      _MX_FLAG,
      _BACK_MX_FLAG,
      _TLD_FLAG,
  )

  def __init__(self, name,
               update_url=None,
               query_url='https://www.kew.com/checkip/',
               enabled_flags=None,
               cache_provider_address_seconds=0,
               check_provider_address=True):
    self.name = name
    self.update_url = update_url
    # 'http://domains.google.com/checkip' doesn't work without going through
    # hoops if on IPv6-enabled system because it redirects to https using
    # IPv6.
    self.query_url = query_url
    self.enabled_flags = frozenset(enabled_flags or [])
    self.cache_provider_address_seconds = cache_provider_address_seconds
    self.check_provider_address = check_provider_address

_PROVIDERS = {
    _SIMPLE:Provider(_SIMPLE),
    _EXTENDED:Provider(_EXTENDED,
                       enabled_flags=Provider.generic_optional_flags),
    _EASYDNS:Provider(_EASYDNS,
                      update_url='https://api.cp.easydns.com/dyn/tomato.php',
                      enabled_flags=Provider.generic_optional_flags),
    _GOOGLE:Provider(_GOOGLE,
                     enabled_flags=
                     (_OFFLINE_FLAG,) + (Provider.generic_optional_flags),
                     query_url='https://domains.google.com/checkip',
                     update_url='https://domains.google.com/nic/update'),
    _TUNNEL_BROKER:Provider(_TUNNEL_BROKER,
                            check_provider_address=False, # No hostname to query
                            query_url='http://checkip.dns.he.net/',
                            cache_provider_address_seconds=3600 * 8,
                            update_url='https://ipv4.tunnelbroker.net/'
                            'nic/update'),
}

#
#  UTILITY ROUTINES
#

def _AddrToStr(ipv4_address):
  '''Format an IP address as a string, allowing for it to be None.

  Args:
    ipv4_address Address to format.  May be None.

  Returns:
    If the input is of type Bytes, the address is formatted as a
    string, else the original input is returned.
  '''
  if isinstance(ipv4_address, bytes):
    return socket.inet_ntoa(ipv4_address)

  return ipv4_address

def _PreparseArguments(args):
  '''Simple preliminary parse to determine how to parse full flags.

  Args:
    Command line arguments.

  Returns:
    tuple with:
    - default provider to base full parsing on
    - whether or not full configuration is needed (that is, that NO
      configuration files) were specified on the command line
  '''
  preparser = argparse.ArgumentParser(
      description='Dynamic DNS client provider',
      add_help=False)

  provider = _PROVIDERS[_EXTENDED]
  is_configuration_needed = False

  _BuildGeneralArguments(preparser)
  _BuildProviderArguments(preparser, provider, is_configuration_needed)
  _BuildClientArguments(preparser, provider, is_configuration_needed)
  _BuildFileArguments(preparser, filetype=str)

  flags = vars(preparser.parse_known_args(args)[0])
  provider = flags[_PROVIDER_NAME_FLAG]
  is_configuration_needed = _CONFIGURATION_FILE_FLAG not in flags

  return (provider, is_configuration_needed)

def _Lower(text):
  '''Lower case the provided string.'''
  return text.lower()

def _BuildGeneralArguments(parser):
  '''Add general program related switches to the command line parser.'''
  general = parser.add_argument_group('General', 'General Program flags')
  general.add_argument('--version',
                       '-v',
                       help='Print the program version',
                       action='version',
                       version=f'%(prog)s {__copyright__}')

  general.add_argument(_COMMAND_PREFIX + _PROVIDER_NAME_FLAG,
                       '-P',
                       choices=sorted(_PROVIDERS.keys()),
                       default=_SIMPLE,
                       type=_Lower,
                       help='Provide defaults (such as the server update URL) '
                       'and set '
                       'restrictions consistent with the specified provider')
  general.add_argument(_COMMAND_PREFIX + _LOG_LEVEL_FLAG,
                       '-l',
                       choices=(_LOG_LEVELS.keys()),
                       type=_Lower,
                       default=argparse.SUPPRESS,
                       help='Logging level. '
                       'Default is run the first pass at level DEBUG and then '
                       'switch to INFO.')

  general.add_argument(
      _COMMAND_PREFIX + _POLL_INTERVAL_SECONDS_FLAG,
      '-i',
      type=int,
      metavar='SECONDS',
      default=argparse.SUPPRESS,
      help='Interval in seconds to poll for changes to the client IP '
      'address. '
      'Default is not to poll, but instead exit after performing '
      'processing once. '
      'Note that a password cannot be specified on the command '
      'line when using this flag; it be must loaded from a configuration file '
      'written with the {}{} flag instead.'.format(_COMMAND_PREFIX,
                                                   _SAVE_FILE_FLAG))


def _BuildProviderArguments(parser, provider, is_configuration_needed):
  '''Add provider server-side related switches to the command line parser.'''

  url_required = is_configuration_needed and not provider.update_url
  url_default = provider.update_url or argparse.SUPPRESS

  server = parser.add_argument_group('Provider', 'DNS Service provider flags')

  server.add_argument(_COMMAND_PREFIX + _USERNAME_FLAG, '-U',
                      default=argparse.SUPPRESS,
                      required=is_configuration_needed,
                      help='User name to authenicate as on provider server')
  server.add_argument(_COMMAND_PREFIX + _PASSWORD_FLAG,
                      '-p',
                      required=is_configuration_needed,
                      default=argparse.SUPPRESS,
                      help='Password/authorization token on provider server')
  server.add_argument(
      _COMMAND_PREFIX + _UPDATE_URL_FLAG,
      '-u',
      metavar='URL',
      required=url_required,
      default=url_default,
      help='DNS service provider web address for IP address updates. '
      'Default for provider "{}" is {}'.format(provider.name,
                                               provider.update_url))

  exclusive = server.add_mutually_exclusive_group()
  exclusive.add_argument(_COMMAND_PREFIX + _CHECK_PROVIDER_ADDRESS,
                         '-k',
                         default=provider.check_provider_address,
                         action='store_true',
                         help='Check the current address reported for the '
                         'hostname (specified by {}{} by DNS, '
                         'and skip updating the '
                         'provider if the address reported by DNS is '
                         'correct'.format(_COMMAND_PREFIX, _HOSTNAME_FLAG))
  exclusive.add_argument(_COMMAND_PREFIX + _NO_PREFIX + _CHECK_PROVIDER_ADDRESS,
                         '-K',
                         dest=_CHECK_PROVIDER_ADDRESS,
                         default=argparse.SUPPRESS,
                         action='store_false',
                         help='Do not check the current client address set at '
                         'the provider when polling.')

  exclusive = server.add_mutually_exclusive_group()
  exclusive.add_argument(_COMMAND_PREFIX + _CACHE_PROVIDER_ADDRESS_SECONDS,
                         '-c',
                         default=provider.cache_provider_address_seconds,
                         metavar='SECONDS',
                         type=int,
                         help='When polling via the {}{} flag, '
                         'remember the address currently set at the provider '
                         'for the specified number of seconds, '
                         'and do not attempt to update the provider if the '
                         'current client public address still matches '
                         'it during this period.'.format(
                             _COMMAND_PREFIX, _POLL_INTERVAL_SECONDS_FLAG))


def _BuildClientArguments(parser, provider, is_configuration_needed):
  '''Add client-side switches to the command line parser.'''

  # Client configuration flags
  client = parser.add_argument_group('Client', 'Client specification flags')

  client.add_argument(_COMMAND_PREFIX + _HOSTNAME_FLAG,
                      '-H',
                      required=is_configuration_needed,
                      help='Name of dynamic host to update')

  exclusive = client.add_mutually_exclusive_group()
  exclusive.add_argument(_COMMAND_PREFIX + _MYIP_FLAG,
                         '-m',
                         dest=_MYIP_FLAG,
                         type=socket.inet_aton,
                         default=argparse.SUPPRESS,
                         help='Dynamic IP address to assign to host; default '
                         'is query the URL specified by {}{} using '
                         'IPv4.'.format(_COMMAND_PREFIX,
                                        _QUERY_URL_FLAG))
  exclusive.add_argument(_COMMAND_PREFIX + _OFFLINE_FLAG,
                         '-o',
                         default=argparse.SUPPRESS,
                         action='store_const',
                         const='yes',
                         help='Set this host to a provider dependent offline '
                         ' status. ')

  exclusive = client.add_mutually_exclusive_group()
  exclusive.add_argument(_COMMAND_PREFIX + _QUERY_URL_FLAG,
                         '-q',
                         default=provider.query_url,
                         metavar='URL',
                         help='URL which returns the current IPv4 address '
                         'of the client. '
                         'The default query URL is '
                         '{}'.format(provider.query_url))
  exclusive.add_argument(_COMMAND_PREFIX + _NO_PREFIX + _QUERY_URL_FLAG,
                         '-Q',
                         dest=_QUERY_URL_FLAG,
                         default=argparse.SUPPRESS,
                         action='store_const',
                         const=None,
                         help='Do not query the current address of the host '
                         'before updating')

  if _TLD_FLAG in provider.enabled_flags:
    client.add_argument(_COMMAND_PREFIX + _TLD_FLAG,
                        '-t',
                        default=argparse.SUPPRESS,
                        help='Top level of domain to update.')

  if _MX_FLAG in provider.enabled_flags:
    client.add_argument(_COMMAND_PREFIX + _MX_FLAG,
                        '-x',
                        default=argparse.SUPPRESS,
                        action='store_true',
                        help='Set the specified host as MX (mail) host for '
                             'the specified domain.')

  if _WILDCARD_FLAG in provider.enabled_flags:
    exclusive = client.add_mutually_exclusive_group()
    exclusive.add_argument(_COMMAND_PREFIX + _WILDCARD_FLAG,
                           '-w',
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='ON',
                           help='Set the specified host as wildcard host for '
                                'the specified domain.')
    exclusive.add_argument(_COMMAND_PREFIX + _NO_PREFIX + _WILDCARD_FLAG,
                           '-W',
                           dest=_WILDCARD_FLAG,
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='OFF',
                           help='Set the specified host as wildcard host for '
                                'the specified domain.')

  if _BACK_MX_FLAG in provider.enabled_flags:
    exclusive = client.add_mutually_exclusive_group()
    exclusive.add_argument(_COMMAND_PREFIX + _BACK_MX_FLAG,
                           '-b',
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='YES',
                           help='Set a vendor dependent backup MX (mail) host '
                                'for this hostname')
    exclusive.add_argument(_COMMAND_PREFIX + _NO_PREFIX + _BACK_MX_FLAG,
                           '-B',
                           dest=_BACK_MX_FLAG,
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='NO',
                           help='Delete the vendor dependent backup MX (mail) '
                                'host for this hostname')


def _BuildFileArguments(parser, filetype=None):
  '''Add file related switches to the command line parser.'''
  persistence = parser.add_argument_group('Persistance',
                                          'File save/load flags')

  exclusive = persistence.add_mutually_exclusive_group()
  exclusive.add_argument(_COMMAND_PREFIX + _SAVE_FILE_FLAG,
                         '-s',
                         default=argparse.SUPPRESS,
                         metavar='OUTPUT-FILE',
                         type=(filetype or argparse.FileType('wb')),
                         help='Name of a configuration file to write for '
                         'later use. '
                         'The file must not exist. '
                         'When this flag is specified, the file is only '
                         'written; no server update is performed.')
  exclusive.add_argument(_CONFIGURATION_FILE_FLAG,  # positional!
                         default=argparse.SUPPRESS,
                         metavar='FILE', # ('FILE-1', 'FILE-2'),
                         nargs='*',
                         type=(filetype or argparse.FileType('rb')),
                         help='Load configuration file(s) previously written '
                         'with the {}{} flag and process the provider defined '
                         'in each. '
                         'The use of saved configuration files is the '
                         'only way to have the program process more than one '
                         'update per invocation.'.format(_COMMAND_PREFIX,
                                                         _SAVE_FILE_FLAG))


def _CheckRequired(args, parser):
  '''Verify all required arguments are specified.'''
  flags = vars(args)
  if _CONFIGURATION_FILE_FLAG in flags:
    return
  required = [_UPDATE_URL_FLAG, _HOSTNAME_FLAG, _USERNAME_FLAG, _PASSWORD_FLAG]
  missing = [f for f in required if f not in flags or not flags[f]]
  if missing:
    parser.error('The flag(s) {} are missing. '
                 'They must be provided either on the command '
                 'line or from a configuration file, and their values must '
                 'not be empty.'.format(
                     ', '.join([_COMMAND_PREFIX + f for f in missing])))
    parser.exit(5)


def _CheckConflicts(args, parser):
  '''Check conflicting options have been not specified.'''
  flags = vars(args)

  # Almost everything conflicts with loading configuration files, so we only
  # check for what's valid or its default.
  allowed = set((_CONFIGURATION_FILE_FLAG,
                 _LOG_LEVEL_FLAG,
                 _POLL_INTERVAL_SECONDS_FLAG))
  restricted = set([_CONFIGURATION_FILE_FLAG, _POLL_INTERVAL_SECONDS_FLAG])
  for restricting_option in restricted:
    if restricting_option in flags:
      conflicts = [f for f in flags
                   if f not in allowed
                   and flags[f] != parser.get_default(f)]
      if conflicts:
        options = [_COMMAND_PREFIX + option
                   for option in allowed if option not in restricted]
        conflicts = [_COMMAND_PREFIX + conflict for conflict in conflicts]
        parser.error(
            'Options not allowed:\n\t{}\n\n'
            'When loading configuration(s) from file(s) and optionally running '
            'continuously, only the following additional options may be '
            'specified on the command line:\n\t{}'.format(
                '\n\t'.join(sorted(conflicts)),
                '\n\t'.join(sorted(options)),
                prefix=_COMMAND_PREFIX))
        parser.exit(3)

  conflict_tuples = [
      (_SAVE_FILE_FLAG,
       (_QUERY_URL_FLAG, _MYIP_FLAG)),
      (_MYIP_FLAG,
       (_QUERY_URL_FLAG, _POLL_INTERVAL_SECONDS_FLAG)),
  ]

  for flag, others in conflict_tuples:
    if flag in flags and flags[flag] != parser.get_default(flag):
      conflicts = [f for f in others
                   if f in flags and flags[f] != parser.get_default(f)]

      if conflicts:
        parser.error('The {prefix}{} flag conflicts with the {} flag(s).\n\t'
                     'The conflict may actually be with related flags, '
                     'for example '
                     'multiple flags implicitly affect the {prefix}{} '
                     ' flag.'.format(
                         flag,
                         ' '.join([_COMMAND_PREFIX + f for f in conflicts]),
                         _MYIP_FLAG, prefix=_COMMAND_PREFIX))
        parser.exit(4)


def _BuildCommandLineParser(args):
  '''Build up the flags for parsing the command line flags.

  Returns:
    ArgumentParser with all valid (possibly conflicting flags)
  '''
  # examine command line for arguments which affect other arguments
  (provider_name, is_configuration_needed) = _PreparseArguments(args)
  provider = _PROVIDERS[provider_name]

  parser = argparse.ArgumentParser(
      description='Dynamic DNS client',
      add_help=True,
      epilog='The above listed flags are valid for provider "{}". '
      'For the flags valid for another provider, specify the '
      '{prefix}{} flag '
      'with the {prefix}help flag on the command '
      'line.\n{copyright}'.format(provider.name,
                     _PROVIDER_NAME_FLAG,
                     prefix=_COMMAND_PREFIX,
                     copyright=__copyright__))

  _BuildGeneralArguments(parser)
  _BuildProviderArguments(parser, provider, is_configuration_needed)
  _BuildClientArguments(parser, provider, is_configuration_needed)
  _BuildFileArguments(parser)

  args = parser.parse_args()
  _CheckRequired(args, parser)
  _CheckConflicts(args, parser)
  return args


def _SaveConfiguration(file_handle, flags):
  '''Save provider flags for later retrieval by _LoadConfiguration.'''
  try:
    configuration = dict(flags)
    del configuration[_SAVE_FILE_FLAG]
    pickled = pickle.dumps(configuration, pickle.HIGHEST_PROTOCOL)
    # b32 encoding is used as a slightly more subtle obfuscation than base 64.
    # This does nothing more than preventing accidently leaking a password to
    # an honest person; it makes no real attempt to hide information from prying
    # eyes.
    file_handle.write(base64.b32encode(pickled))
  finally:
    file_handle.close()

  _LOGGER.debug('Wrote %s with:', flags[_SAVE_FILE_FLAG].name)
  for flag in sorted(configuration):
    _LOGGER.debug('\t%s\t%s', flag, configuration[flag])


def _LoadConfiguration(file_handle):
  '''Load provider flags previously saved by _SaveConfiguration.'''
  try:
    pickled = base64.b32decode(file_handle.read())
    configuration = pickle.loads(pickled)
  finally:
    file_handle.close()
  return configuration


def _GetRecordedDNSAddress(configuration):
  '''Report IPv4 address of specified hostname as known by provider.'''
  if configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][1] > time.time():
    _LOGGER.debug(
        'Using client %s cached address %s, entry expires at %s',
        configuration[_HOSTNAME_FLAG],
        _AddrToStr(configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][0]),
        time.ctime(configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][1]))
    return configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][0]

  if configuration[_CHECK_PROVIDER_ADDRESS]:
    try:
      address = socket.gethostbyname(configuration[_HOSTNAME_FLAG])
      _LOGGER.debug("Client %s address as reported by DNS is %s",
                    configuration[_HOSTNAME_FLAG],
                    address)
      return socket.inet_aton(address)
    except (IOError) as ex:
      _LOGGER.debug('Unable to query DNS for %s, error %s',
                    configuration[_HOSTNAME_FLAG],
                    str(ex))
      return None

  # checking of current address not enabled.
  return None


def _QueryCurrentIPAddress(configuration,
                           override_url=None,
                           level=logging.DEBUG):
  '''Query a remote webserver to determine our possibly NATted address.'''

  def _CreateConnection(hostname_port, timeout=None, source_address=None):
    '''IPv4-only replacement for HTTPConnnection create_connection'''
    hostname, port = hostname_port

    try:
      # The secret sauce is to only query IPv4 family addresses, so we only get
      # an IPv4 address back that we connect from OUR IPv4 address to.
      res = socket.getaddrinfo(hostname,
                               port,
                               socket.AF_INET,
                               socket.SOCK_STREAM)
      address_family, socktype, proto, _, hostaddr_port = res[0]
    except Exception as err:
      _LOGGER.error("Cannot look up client %s; exception:\n%s",
                    hostname,
                    err)
      raise

    sock = socket.socket(address_family, socktype, proto)
    if (timeout is not None and
        timeout is not socket._GLOBAL_DEFAULT_TIMEOUT):  # pylint: disable=W0212
      sock.settimeout(timeout)
    if source_address:
      sock.bind(source_address)
    sock.connect(hostaddr_port)
    return sock

  if _QUERY_URL_FLAG not in configuration or not configuration[_QUERY_URL_FLAG]:
    return None

  url = override_url or configuration[_QUERY_URL_FLAG]
  url_parts = urllib.parse.urlsplit(url)
  _LOGGER.debug("Querying %s for IPv4 address of client", url)

  if url_parts.scheme == 'http':
    connection = http.client.HTTPConnection(
        url_parts.hostname,
        port=(url_parts.port or http.client.HTTP_PORT))
  elif url_parts.scheme == 'https':
    connection = http.client.HTTPSConnection(
        url_parts.hostname,
        port=(url_parts.port or http.client.HTTPS_PORT))
  else:
    raise NotImplementedError(
        'Scheme "{}" not supported for IP address look up'.format(
            url_parts.scheme))

  # The secret sauce for both HTTP and HTTPS connections is our override of the
  # _create_connection which only queries IPv4 server addresses and thus
  # connects via the client's IPv4 address. (A query of the client address via
  # IPv6 obviously returns an IPv6 address.)
  connection._create_connection = _CreateConnection    # pylint: disable=W0212

  try:
    connection.connect()
    connection.request('GET',
                       url,
                       headers={'User-Agent':_USER_AGENT})
    response = connection.getresponse()

    if response.status == HTTPStatus.OK:
      data = response.read().decode()
      match = _ADDRESS_RE.search(data)
      if match:
        _LOGGER.debug(
            '%s reports client public address as %s',
            url,
            match.group(0))
        return socket.inet_aton(match.group(0))
      _LOGGER.error(
          'No IP address returned by %s: %s ...',
          url,
          data[:80])
      return None

    if response.status in (HTTPStatus.MOVED_PERMANENTLY,
                           HTTPStatus.FOUND,
                           HTTPStatus.SEE_OTHER,
                           HTTPStatus.TEMPORARY_REDIRECT):
      # Recursively handle redirect requests explicitly using IPv4
      redirect = response.getheader('Location')
      _LOGGER.debug(
          'Redirecting (%s) %s to %s',
          response.status,
          url_parts.geturl(),
          redirect)
      return _QueryCurrentIPAddress(configuration,
                                    override_url=redirect,
                                    level=level)

    raise urllib.error.HTTPError(url,
                                 response.status,
                                 response.reason,
                                 response.getheaders(),
                                 response.fp)
  except IOError as ex:
    _LOGGER.warning('Error retrieving current IP address: %s', str(ex))
    raise
  finally:
    connection.close()

  return None


def _GetCurrentPublicIPAddress(configuration,
                               client_query_cache,
                               level=logging.DEBUG):
  '''Determine the current public client address to send to the provider'''
  if _OFFLINE_FLAG in configuration:
    current_client_address = _OFFLINE_FLAG
  elif _MYIP_FLAG in configuration:
    current_client_address = configuration[_MYIP_FLAG]
  elif configuration[_QUERY_URL_FLAG]:
    query_url = configuration[_QUERY_URL_FLAG]
    if query_url in client_query_cache:
      current_client_address = client_query_cache[query_url]
    else:
      current_client_address = _QueryCurrentIPAddress(configuration,
                                                      level=level)
      if current_client_address:
        client_query_cache[query_url] = current_client_address
  else:
    # We're relying on the request to the server to determine the client address
    current_client_address = None
  return current_client_address


def _StorePassword(url_prefix, configuration):
  '''If not already cached, store the password for the specified URL prefix.'''
  # Following code (and associated code in Main()) based on stackoverflow.com
  # example at http://goo.gl/WJldUm
  (user, _) = _PASSWORD_MANAGER.find_user_password(None, url_prefix)
  if not user:
    _LOGGER.info(
        "Adding authenication data for URL %s (user %s) to password manager",
        url_prefix,
        configuration[_USERNAME_FLAG])

    # Because we have put None as the realm the start it will always use this
    # username/password combination for urls for which `url` is a super-url
    _PASSWORD_MANAGER.add_password(
        None,
        url_prefix,
        configuration[_USERNAME_FLAG],
        configuration[_PASSWORD_FLAG])


def _UpdateDNSAddress(configuration, current_client_address):
  '''Update the providers address for our client.'''
  parameters = []

   # URL Parameters with values in the configuration
  for flag in [_HOSTNAME_FLAG,
               _BACK_MX_FLAG,
               _WILDCARD_FLAG,
               _TLD_FLAG]:
    if flag in configuration:
      parameters.append('{}={}'.format(flag, configuration[flag]))

  # Binary URL parameters with no value
  for flag in [_MX_FLAG]:
    if flag in configuration and configuration[flag]:
      parameters.append(flag)

  request = urllib.request.Request(
      '{}?{}'.format(configuration[_UPDATE_URL_FLAG], '&'.join(parameters)),
      headers={'User-Agent':_USER_AGENT})

  _StorePassword(request.get_full_url(), configuration)

  # We add this LAST so it doesn't affect the URL passed to _StorePassword for
  # the site.

  # The current client address, our reason to exist, is special because the
  # value is not part of the configuration dictionary.  If it is not included,
  # then the update server is assumed to "Do The Right Thing" by examining the
  # connection metadata

  if _OFFLINE_FLAG in configuration:
    parameters.append(
        '{}={}'.format(_OFFLINE_FLAG, configuration[_OFFLINE_FLAG]))
  elif current_client_address:
    parameters.append('{}={}'.format(
        _MYIP_FLAG, _AddrToStr(current_client_address)))

  # Now rebuild the request with flags added after _StorePassword was called
  request = urllib.request.Request(
      '{}?{}'.format(configuration[_UPDATE_URL_FLAG], '&'.join(parameters)),
      headers={'User-Agent':_USER_AGENT})

  try:
    _LOGGER.debug('Invoking: %s', request.get_full_url())
    # authentication is now handled automatically for us
    handle = urllib.request.urlopen(request)

    for line in handle:
      line = line.decode().strip()

      if line:
        token = line.split()
        if token[0] in ['good', 'nochg', 'NOERROR']:
          _LOGGER.debug(
              'Success response "%s" from %s for host %s',
              token[0],
              request.origin_req_host,
              configuration[_HOSTNAME_FLAG])
        else:
          _LOGGER.warning(
              'ERROR response "%s" from %s for host %s: %s',
              token[0],
              request.origin_req_host,
              configuration[_HOSTNAME_FLAG],
              line)
          raise IOError(
              '{} update via {} failed: {}'.format(
                  configuration[_HOSTNAME_FLAG],
                  request.origin_req_host,
                  line))
  except urllib.error.URLError as ex:
    _LOGGER.error('Exception processing %s: %s',
                  request.get_full_url(),
                  str(ex))
    raise ex


def _ProcessUpdate(configuration, client_query_cache):
  '''Perform processing to update a DNS single configuration.'''
  hostname = configuration[_HOSTNAME_FLAG]
  try:
    current_client_address = _GetCurrentPublicIPAddress(configuration,
                                                        client_query_cache)
    recorded_dns_address = _GetRecordedDNSAddress(configuration)
    if (not recorded_dns_address or
        recorded_dns_address != current_client_address):
      # reset any cache entry, then perform the actual update.
      configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS] = (None, 0)
      _UpdateDNSAddress(configuration, current_client_address)
      # After update, refresh cache entry
      configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS] = (
          current_client_address,
          time.time() + configuration[_CACHE_PROVIDER_ADDRESS_SECONDS])
      _LOGGER.info(
          'Address for %s updated from %s to %s',
          hostname,
          _AddrToStr(recorded_dns_address),
          _AddrToStr(current_client_address))
    else:
      _LOGGER.debug(
          'No update needed for %s, address is %s',
          hostname,
          _AddrToStr(recorded_dns_address))
  except IOError as ex:
    _LOGGER.error(
        f'{type(ex).__name__} Exception during processing for '
        f'{hostname}: {str(ex)}')
    configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS] = (None, 0)

def _InitializeLogging(logger):
  '''Set logging for console and system log.'''
  logger.setLevel(logging.DEBUG)

  datefmt = '%m-%d %H:%M:%S '
  short_format = ' '.join(
      [
          '%(filename)s[%(process)d]',
          '%(levelname)s',
          '%(message)s',
      ])
  full_format = '%(asctime)s' + short_format
  formatter = logging.Formatter(fmt=full_format, datefmt=datefmt)

  console_handler = logging.StreamHandler()
  console_handler.setFormatter(formatter)
  logger.addHandler(console_handler)

  address = ('localhost', logging.handlers.SYSLOG_UDP_PORT)
  for path in ['/var/run/syslog', # Mac OS X
               '/dev/log',        # Linux
               '/var/run/log']:   # FreeBSD
    if os.path.exists(path):
      address = path
      break

  syslog_handler = logging.handlers.SysLogHandler(
      address=address,
      facility=logging.handlers.SysLogHandler.LOG_DAEMON)
  syslog_handler.setFormatter(logging.Formatter(fmt=short_format))
  logger.addHandler(syslog_handler)
  logger.info("%s version %s begins", os.path.basename(__file__), __version__)
  return logger


def _Main():
  '''Main program, parses arguments and either saves or processes them.'''

  _InitializeLogging(_LOGGER)
  flags = vars(_BuildCommandLineParser(sys.argv[1:]))

  # Configure all calls to urllib.urlopen to use a handler with its
  # password manager. One must nake sure not to include the protocol in with
  # the URL, or HTTPPasswordMgrWithDefaultRealm will be very confused.
  # One must (of course) use the protocol when fetching the page though.
  authhandler = urllib.request.HTTPBasicAuthHandler(_PASSWORD_MANAGER)
  opener = urllib.request.build_opener(authhandler)
  urllib.request.install_opener(opener)

  if _LOG_LEVEL_FLAG in flags:
    _LOGGER.setLevel(_LOG_LEVELS[flags[_LOG_LEVEL_FLAG]])

  # we have a file to save, do so and then exit without updating any provider
  if _SAVE_FILE_FLAG in flags:
    _SaveConfiguration(flags[_SAVE_FILE_FLAG], flags)
    sys.exit(0)

  # Load any stored configurations
  configurations = []
  if _CONFIGURATION_FILE_FLAG in flags:
    for file_handle in flags[_CONFIGURATION_FILE_FLAG]:
      configurations.append(_LoadConfiguration(file_handle))

  # If no files are loaded, our only configuration is the details of what we
  # just read from the command line.
  if not configurations:
    configurations = [flags]

  # Initialize empty and expired provider cache information
  for configuration in configurations:
    configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS] = (None, 0)

  first_pass = True
  while first_pass or _POLL_INTERVAL_SECONDS_FLAG in flags:
    # new client address cache every processing pass
    client_query_cache = {}
    for configuration in configurations:
      _ProcessUpdate(configuration, client_query_cache)

    if _POLL_INTERVAL_SECONDS_FLAG in flags:
      _LOGGER.debug('Sleeping for %d seconds',
                    flags[_POLL_INTERVAL_SECONDS_FLAG])
      time.sleep(flags[_POLL_INTERVAL_SECONDS_FLAG])

    if first_pass:
      first_pass = False
      # By default, report less after the first pass
      if not _LOG_LEVEL_FLAG in flags:
        _LOGGER.setLevel(logging.INFO)

if __name__ == '__main__':
  _Main()
