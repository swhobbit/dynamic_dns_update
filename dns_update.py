#!/usr/bin/python
'''
Client for Dynamic DNS updates.  Supports EasyDNS, Google, Hurricane Electrics's
Tunnelbroker.net, and many generic services.
'''

# pylint: disable=I0011


import argparse
import base64
import httplib
import pickle
import socket
import sys
import time
import urlparse
import urllib2

__AUTHOR__ = 'Kendra Electronic Wonderworks (uupc-help@kew.com)'
__VERSION__ = '0.9.2'

_USER_AGENT = 'dns_update.py by {} version {}'.format(__AUTHOR__, __VERSION__)

# Provide Server side flags
_PASSWORD_FLAG = 'password'
_USERNAME_FLAG = 'username'
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

# Not a flag, but stored in the configuration to cache it
_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS = '_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS'

# Providers
_SIMPLE = 'simple'
_EXTENDED = 'extended'
_GOOGLE = 'google'
_EASYDNS = 'easydns'
_TUNNEL_BROKER = 'tunnelbroker'

_COMMAND_PREFIX = '--'
_NO_PREFIX = 'no_'

class Provider(object):
  """Holder for provider specific metadata."""
  generic_optional_flags = frozenset([
      _WILDCARD_FLAG,
      _MX_FLAG,
      _BACK_MX_FLAG,
      _TLD_FLAG,
      _QUERY_URL_FLAG,
  ])

  def __init__(self, name,
               update_url=None,
               query_url='https://domains.google.com/checkip',
               enabled_flags=None,
               cache_provider_address_seconds=0,
               check_provider_address=True):
    self.name = name
    self.update_url = update_url
    # 'http://domains.google.com/checkip' doesn't work if on IPv6-enabled
    # system work because it redirects to https using IPv6.
    self.query_url = query_url
    self.enabled_flags = frozenset(enabled_flags or [])
    self.cache_provider_address_seconds = cache_provider_address_seconds
    self.check_provider_address = check_provider_address

_PROVIDERS = {
    _SIMPLE:Provider(_SIMPLE),
    _EXTENDED:Provider(_EXTENDED,
                       enabled_flags=Provider.generic_optional_flags),
    _EASYDNS:Provider(_EASYDNS,
                      update_url='https://members.easydns.com/dyn/dyndns.php',
                      enabled_flags=Provider.generic_optional_flags),
    _GOOGLE:Provider(_GOOGLE,
                     enabled_flags=[_QUERY_URL_FLAG],
                     update_url='https://domains.google.com/nic/update'),
    _TUNNEL_BROKER:Provider(_TUNNEL_BROKER,
                            check_provider_address=False, # No hostname to query
                            cache_provider_address_seconds=1800,
                            update_url='https://ipv4.tunnelbroker.net/'
                            'nic/update'),
}


def _AddrToStr(ipv4_adddress):
  """Format an IP address as a string, allowing for it to be None"""
  if ipv4_adddress:
    return socket.inet_ntoa(ipv4_adddress)
  else:
    return '(none)'

def _PreparseArguments(args):
  """Simple preliminary parse to determine how to parse full flags."""
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

def _BuildGeneralArguments(parser):
  """Add general program related switches to the command line parser."""
  general = parser.add_argument_group('General', 'General Program flags')
  general.add_argument('--version',
                       '-v',
                       help='Print the program version',
                       action='version',
                       version='%(prog)s by {} version {}'.format(
                           __AUTHOR__, __VERSION__))

  general.add_argument(_COMMAND_PREFIX + _PROVIDER_NAME_FLAG,
                       '-P',
                       choices=sorted(_PROVIDERS.keys()),
                       default=_SIMPLE,
                       help='Provide defaults (such as the server update URL) '
                       'and set '
                       'restrictions consistent with the specified provider')

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
  """Add provider server-side related switches to the command line parser."""

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
  """Add client-side configration switches to the command line parser."""

  # Client configuration flags
  client = parser.add_argument_group('Client', 'Client specification flags')

  client.add_argument(_COMMAND_PREFIX + _HOSTNAME_FLAG,
                      '-H',
                      required=is_configuration_needed,
                      help='Name of dynamic jost to update')

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
                         dest=_MYIP_FLAG,
                         action='store_const',
                         const=socket.inet_aton('0.0.0.0'),
                         help='Set this host to a provider dependent offline '
                         ' status ')

  if _QUERY_URL_FLAG in provider.enabled_flags:
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
  """Add file related switches to the command line parser."""
  persistence = parser.add_argument_group('Persistance',
                                          'File save/load flags')

  exclusive = persistence.add_mutually_exclusive_group()
  exclusive.add_argument(_COMMAND_PREFIX + _SAVE_FILE_FLAG,
                         '-s',
                         default=argparse.SUPPRESS,
                         metavar='OUTPUT-FILE',
                         type=(filetype or argparse.FileType('wx')),
                         help='Name of a configuration file to write for '
                         'later use. '
                         'The file must not exist. '
                         'When this flag is specified, the file is only '
                         'written; no server update is performed.')
  exclusive.add_argument(_CONFIGURATION_FILE_FLAG,  # positional!
                         default=argparse.SUPPRESS,
                         metavar='FILE', # ('FILE-1', 'FILE-2'),
                         nargs='*',
                         type=(filetype or argparse.FileType('r')),
                         help='Load configuration file(s) previously written '
                         'with the {}{} flag and process the provider defined '
                         'in each. '
                         'The use of saved configuration files is the '
                         'only way to have the program process more than one '
                         'update per invocation.'.format(_COMMAND_PREFIX,
                                                         _SAVE_FILE_FLAG))


def _CheckRequired(args, parser):
  """Verify all required argumewnts are specified."""
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
  """Check conflicting options have not specified."""
  flags = vars(args)

  # Almost everything conflicts with loading configuration files, so we only
  # check for what's valid or its default.
  if _CONFIGURATION_FILE_FLAG in flags:
    conflicts = [f for f in flags
                 if f not in [_CONFIGURATION_FILE_FLAG,
                              _POLL_INTERVAL_SECONDS_FLAG]
                 and flags[f] != parser.get_default(f)]
    if conflicts:
      parser.error('Only the {}{} flag may specified on the command line when '
                   'loading configurations from one more files.'.format(
                       _COMMAND_PREFIX, _POLL_INTERVAL_SECONDS_FLAG))
      parser.exit(3)

  conflict_tuples = [
      (_POLL_INTERVAL_SECONDS_FLAG,
       (_MYIP_FLAG, _SAVE_FILE_FLAG, _PASSWORD_FLAG)),
      (_MYIP_FLAG, (_QUERY_URL_FLAG, _SAVE_FILE_FLAG)),
  ]
  for flag, others in conflict_tuples:
    if flag in flags and flags[flag] != parser.get_default(flag):
      conflicts = [f for f in others
                   if f in flags and flags[f] != parser.get_default(f)]
      if conflicts:
        parser.error('The {}{} flag conflicts with the {} flag(s). '
                     'The conflict may actually be with related flags, '
                     'for example '
                     'multiple flags implicitly affect the {}{} flag.'.format(
                         _COMMAND_PREFIX, flag,
                         ' '.join([_COMMAND_PREFIX + f for f in conflicts]),
                         _COMMAND_PREFIX, _MYIP_FLAG))
        parser.exit(4)


def _BuildCommandLineParser(args):
  """Build up the flags for parsing the command line flags.

  Returns:
    ArgumentParser with all valid (possibly conflicting flags)
  """
  # examine command line for arguments which affect other arguments
  (provider_name, is_configuration_needed) = _PreparseArguments(args)
  provider = _PROVIDERS[provider_name]

  parser = argparse.ArgumentParser(
      description='Dynamic DNS client',
      add_help=True,
      epilog='The above listed flags are valid for provider "{}". '
      'For the flags valid for another provider, specifiy the {}{} flag '
      'with the {}help flag on the command '
      'line.'.format(provider.name,
                     _COMMAND_PREFIX,
                     _PROVIDER_NAME_FLAG,
                     _COMMAND_PREFIX))

  _BuildGeneralArguments(parser)
  _BuildProviderArguments(parser, provider, is_configuration_needed)
  _BuildClientArguments(parser, provider, is_configuration_needed)
  _BuildFileArguments(parser)

  args = parser.parse_args()
  _CheckRequired(args, parser)
  _CheckConflicts(args, parser)
  return args


def _SaveConfiguration(file_handle, flags):
  """Save provider flags for later retrieval by _LoadConfiguration."""
  try:
    configuration = dict(flags)
    del configuration[_SAVE_FILE_FLAG]
    pickled = pickle.dumps(configuration, pickle.HIGHEST_PROTOCOL)
    file_handle.write(base64.b32encode(pickled))
  finally:
    file_handle.close()

  print 'Wrote', file_handle.name, 'with:'
  for flag in sorted(configuration):
    print '\t{}\t{}'.format(flag, configuration[flag])


def _LoadConfiguration(file_handle):
  """Load provider flags previously saved by _SaveConfiguration."""
  try:
    pickled = base64.b32decode(file_handle.read())
    configuration = pickle.loads(pickled)
  finally:
    file_handle.close()
  return configuration


def _GetRecordedDNSAddress(configuration):
  """Report IPv4 address of specified hostname as known by provider."""
  if (_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS in configuration and
      configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][1] > time.time()):
    print 'Using cached address value {}, cache expires at {}'.format(
        _AddrToStr(configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][0]),
        time.ctime(configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][1]))
    return configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS][0]
  elif configuration[_CHECK_PROVIDER_ADDRESS]:
    try:
      return socket.inet_aton(socket.gethostbyname(
          configuration[_HOSTNAME_FLAG]))
    except IOError, _:
      return None
  else:
    # checking not enabled.
    return None

def _QueryCurrentIPAddress(configuration, override_url=None):
  """Query a remote webserver to determine our possibly NATted address."""
  if _QUERY_URL_FLAG not in configuration or not configuration[_QUERY_URL_FLAG]:
    return None

  url_parts = urlparse.urlsplit(override_url or configuration[_QUERY_URL_FLAG])

  # The secret sauce for both HTTP and HTTPS below is the source address of
  # 0.0.0.0, which implicitly forces IPv4 for the connection.
  if url_parts.scheme == 'http':
    connection = httplib.HTTPConnection(
        url_parts.hostname,
        url_parts.port or httplib.HTTP_PORT,
        True,
        None,
        ('0.0.0.0', 0))
  elif url_parts.scheme == 'https':
    # pylint: disable=R0204
    connection = httplib.HTTPSConnection(
        url_parts.hostname,
        url_parts.port or httplib.HTTPS_PORT,
        None,
        None,
        True,
        None,
        ('0.0.0.0', 0))
  else:
    raise NotImplementedError(
        'Scheme "{}" not supported for IP address look up'.format(
            url_parts.scheme))

  try:
    connection.request('GET',
                       urlparse.urlunsplit((None,
                                            None,
                                            url_parts.path,
                                            url_parts.query,
                                            url_parts.fragment)),
                       None,
                       {'User-Agent':_USER_AGENT})
    response = connection.getresponse()

    if response.status == 200:
      # TODO: Consider parsing the line to extract IP address from servers that
      # return extra text in the response.
      data = response.read().strip()
      return socket.inet_aton(data)
    elif response.status in (301, 302, 303, 307):
      # Recursively handle redirect requests
      redirect = response.getheader('Location')
      print 'Redirecting ({}) {} to {}'.format(response.status,
                                               url_parts.geturl(),
                                               redirect)
      return _QueryCurrentIPAddress(configuration, override_url=redirect)
    else:
      print 'Unexpected response from server: {} {}'.format(
          response.status,
          response.reason)
      return None
  except IOError, ex:
    print 'Error retrieving current IP address: {}'.format(ex)
    return None
  finally:
    connection.close()


def _GetCurrentPublicIPAddress(configuration):
  """Determine the current public client address to send to the provider"""
  if _MYIP_FLAG in configuration:
    current_client_address = configuration[_MYIP_FLAG]
  elif _QUERY_URL_FLAG in configuration:
    current_client_address = _QueryCurrentIPAddress(configuration)
  else:
    # We're relying on the request to the server to determine the client address
    current_client_address = None
  return current_client_address


def _UpdateDNSAddress(configuration, current_client_address):
  """Update the providers address for our client."""
  parameters = []

  # The current client address, our reason to exist, is special because the
  # value is not part of the configuration dictionary.  If it is not included,
  # then the update server is assumed to "Do The Right Thing" by examining the
  # connection metadata.
  if current_client_address:
    parameters.append('{}={}'.format(_MYIP_FLAG,
                                     _AddrToStr(current_client_address)))

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

  request = urllib2.Request('{}?{}'.format(configuration[_UPDATE_URL_FLAG],
                                           '&'.join(parameters)),
                            headers={'User-Agent':_USER_AGENT})

  # Following code based on stackoverflow.com example at http://goo.gl/WJldUm
  passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
  passman.add_password(None,
                       request.get_full_url(),
                       configuration[_USERNAME_FLAG],
                       configuration[_PASSWORD_FLAG])
  # because we have put None at the start it will always use this
  # username/password combination for urls for which `url` is a super-url

  authhandler = urllib2.HTTPBasicAuthHandler(passman)
  opener = urllib2.build_opener(authhandler)
  urllib2.install_opener(opener)

  # All calls to urllib2.urlopen will now use our handler.
  # Make sure not to include the protocol in with the URL, or
  # HTTPPasswordMgrWithDefaultRealm will be very confused.
  # You must (of course) use it when fetching the page though.

  try:
    print 'Invoking:', request.get_full_url()
    # authentication is now handled automatically for us
    handle = urllib2.urlopen(request)
    # TODO: parse text response and handle errors
    for line in handle:
      if line.strip():
        print 'Response:', request.get_host(), line.strip()
      return True
  except (urllib2.HTTPError, urllib2.URLError), e:
    print 'Error processing {}: {}'.format(request.get_host(), e)


def _ProcessUpdate(configuration):
  """Perform processing to update a DNS single configuration."""
  try:
    current_client_address = _GetCurrentPublicIPAddress(configuration)
    recorded_dns_address = _GetRecordedDNSAddress(configuration)
    if (not recorded_dns_address or
        recorded_dns_address != current_client_address):
      print 'Recorded address: {}, Current address: {}'.format(
          _AddrToStr(recorded_dns_address),
          _AddrToStr(current_client_address))
      # reset any cache entry, then perform the actual update.
      configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS] = (None, 0)
      if _UpdateDNSAddress(configuration, current_client_address):
        configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS] = (
            current_client_address,
            time.time() + configuration[_CACHE_PROVIDER_ADDRESS_SECONDS])
    else:
      print 'No updated needed, {} address already is {}'.format(
          configuration[_HOSTNAME_FLAG],
          _AddrToStr(recorded_dns_address))
  except IOError, ex:
    print 'Update procesisng failed:', ex
    configuration[_CACHE_OF_CURRENT_IP_ADDRESS_IN_DNS] = (None, 0)

def _Main():
  """Main program, parses arguments and either saves or processes them."""
  flags = vars(_BuildCommandLineParser(sys.argv[1:]))

  # we have a file to save, do so and then exit with updating any provider
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

  first_pass = True
  while first_pass or _POLL_INTERVAL_SECONDS_FLAG in flags:
    first_pass = False
    if _POLL_INTERVAL_SECONDS_FLAG in flags:
      time.sleep(flags[_POLL_INTERVAL_SECONDS_FLAG])
    for configuration in configurations:
      _ProcessUpdate(configuration)

if __name__ == '__main__':
  _Main()
