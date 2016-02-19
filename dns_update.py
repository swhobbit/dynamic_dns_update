#!/usr/bin/python
'''
Client for Dynamic DNS updates.  Supports EasyDNS, Google, Hurricane Electrics's
Tunnelbroker.net, and many generic services.
'''

import argparse
import socket
import sys


# Provide Server side options
_PASSWORD_FLAG = 'password'
_USERNAME_FLAG = 'username'
_PROVIDER_NAME_FLAG = 'provider'
_URL_FLAG = 'url'
_QUERY_URL_FLAG = 'query_url'

# Client options
_TLD_FLAG = 'tld'
_HOSTNAME_FLAG = 'hostname'
_LOCAL_IP_FLAG = 'local_ip'
_MY_IP_FLAG = 'my_ip'
_BACK_MX_FLAG = 'backmx'
_MX_FLAG = 'mx'
_WILDCARD_FLAG = 'wildcard'
_OFFLINE_FLAG = 'offline'

# Internal program options
_CONFIGURATION_FILE_FLAG = 'from'
_SAVE_FILE_FLAG = 'save'
_DELAY_INTERVAL_FLAG = 'delay_interval'

_SWITCH_LIST = [
    _TLD_FLAG,
    _HOSTNAME_FLAG,
    _LOCAL_IP_FLAG,
    _MY_IP_FLAG,
    _BACK_MX_FLAG,
    _MX_FLAG,
    _WILDCARD_FLAG,
    _OFFLINE_FLAG,
    _PASSWORD_FLAG,
    _USERNAME_FLAG,
    _URL_FLAG,
    _QUERY_URL_FLAG,
    _SAVE_FILE_FLAG,
    _DELAY_INTERVAL_FLAG,
]

# Providers
_GENERIC = 'generic'
_GOOGLE = 'google'
_EASYDNS = 'easydns'
_TUNNEL_BROKER = 'tunnelbroker'

_PROVIDERS = [_GENERIC, _EASYDNS, _GOOGLE, _TUNNEL_BROKER]

def _BuildCommandLineParser(args):
  """Build up the options for parsing the command line options.

  Returns:
    ArgumentParser with all valid (possibly conflicting options)
  """
  command_prefix = '--'
  no_prefix = 'no_'

  generic_options = set([_WILDCARD_FLAG,
                         _MX_FLAG,
                         _BACK_MX_FLAG,
                         _TLD_FLAG])
  easydns_options = set(generic_options)
  enable_flag_by_provider = {
      _GENERIC:generic_options,
      _EASYDNS:easydns_options,
      _GOOGLE:set(),
      _TUNNEL_BROKER:set(),
  }

  default_url_by_provider = {
      _GENERIC: None,
      _EASYDNS: 'https://members.easydns.com/dyn/dyndns.php',
      _GOOGLE: 'https://domains.google.com/nic/update',
      _TUNNEL_BROKER: 'https://ipv4.tunnelbroker.net/nic/update',
  }


  # This first parse only determines our provider, which allows determing
  # what options to set.
  preparser = argparse.ArgumentParser(
      description='Dynamic DNS client provider',
      add_help=False)
  preparser.add_argument(command_prefix + _PROVIDER_NAME_FLAG,
                         '-P',
                         choices=_PROVIDERS,
                         default=_GENERIC)
  preparser.add_argument(_CONFIGURATION_FILE_FLAG, # positonal
                         default=argparse.SUPPRESS,
                         metavar='FILE',
                         nargs='*')
  # stuff we don't care about but need to valid to keep from looking position
  for option in _SWITCH_LIST:
    preparser.add_argument(command_prefix + option, default=argparse.SUPPRESS)

  preparser_args = vars(preparser.parse_known_args(args)[0])
  print preparser_args
  provider = preparser_args[_PROVIDER_NAME_FLAG]
  is_configuration_needed = _CONFIGURATION_FILE_FLAG not in preparser_args

  # Now that we have our provider, we can build the main options flag list
  parser = argparse.ArgumentParser(
      description='Dynamic DNS client',
      add_help=True,
      epilog='The above listed options are valid for provider "{}". '
      'For the options of valid for another provider, both the {}{} '
      'and the {}help flag on the command '
      'line.'.format(provider,
                     command_prefix,
                     _PROVIDER_NAME_FLAG,
                     command_prefix))

  general = parser.add_argument_group('General', 'General Program options')

  # We add the provider flag so it shows up in help, and so it can be ignored
  # when parsing the full command line.
  general.add_argument(command_prefix + _PROVIDER_NAME_FLAG,
                       '-P',
                       choices=_PROVIDERS,
                       default=provider,
                       help='Provide defaults (such as server URL) and set '
                       'restrictions consistent with the specified provider')

  general.add_argument(
      command_prefix + _DELAY_INTERVAL_FLAG,
      '-i',
      type=int,
      metavar='SECONDS',
      default=argparse.SUPPRESS,
      help='Interval in seconds to perform poll for changes to the client IP '
      'address. Default is not poll, but instead exit after performing '
      'processing once')

  # File argument(s)
  persistence = parser.add_argument_group('Persistance',
                                          'File save/load options')

  exclusive = persistence.add_mutually_exclusive_group()
  exclusive.add_argument(command_prefix + _SAVE_FILE_FLAG,
                         '-s',
                         default=argparse.SUPPRESS,
                         metavar='OUTPUT-FILE',
                         type=argparse.FileType('w'),
                         help='Configuration file to write for later use')
  exclusive.add_argument(_CONFIGURATION_FILE_FLAG,  # positional!
                         default=argparse.SUPPRESS,
                         metavar='FILE',
                         nargs='*',
                         type=argparse.FileType('r'),
                         help='Configuration file(s)s previously written with '
                         + 'the {}{} option'.format(command_prefix,
                                                    _SAVE_FILE_FLAG))

  # Service provider options
  server = parser.add_argument_group('Provider', 'DNS Service provider options')
  url_default = default_url_by_provider[provider] or argparse.SUPPRESS
  url_required = (is_configuration_needed and
                  not default_url_by_provider[provider])
  server.add_argument(
      command_prefix + _URL_FLAG,
      '-u',
      required=url_required,
      default=url_default,
      help='DNS service provider web address to connect to. '
      'Default for provider "{}" is {}'.format(provider,
                                               url_default))
  server.add_argument(command_prefix + _USERNAME_FLAG, '-U',
                      default=argparse.SUPPRESS,
                      required=is_configuration_needed,
                      help='User name for provider server')
  server.add_argument(command_prefix + _PASSWORD_FLAG,
                      '-p',
                      required=is_configuration_needed,
                      default=argparse.SUPPRESS,
                      help='Password/authorization token for provider server')

  # Client configuration options
  client = parser.add_argument_group('Client', 'Client specification options')

  exclusive = client.add_mutually_exclusive_group()
  exclusive.add_argument(command_prefix + _MY_IP_FLAG,
                         command_prefix + _LOCAL_IP_FLAG,
                         '-l',
                         dest=_MY_IP_FLAG,
                         type=socket.inet_aton,
                         default=argparse.SUPPRESS,
                         help='Dynamic IP address to assign to host; default '
                         'is query the URL specified by {}{} using '
                         'IPv4.'.format(command_prefix,
                                        _QUERY_URL_FLAG))
  exclusive.add_argument(command_prefix + _OFFLINE_FLAG,
                         '-o',
                         default=argparse.SUPPRESS,
                         dest=_MY_IP_FLAG,
                         action='store_const',
                         const=socket.inet_aton('0.0.0.0'),
                         help='Set this host to a provider dependent offline '
                         ' status ')

  default_query_url = 'http://domains.google.com/checkip'
  exclusive.add_argument(command_prefix + _QUERY_URL_FLAG,
                         '-q',
                         default=default_query_url,
                         help='URL which returns the current IPv4 address '
                         'of the client. '
                         'The default URL is {}'.format(default_query_url))

  if _TLD_FLAG in enable_flag_by_provider[provider]:
    client.add_argument(command_prefix + _TLD_FLAG,
                        '-t',
                        default=argparse.SUPPRESS,
                        help='Top level of domain to update.')

  if _MX_FLAG in enable_flag_by_provider[provider]:
    client.add_argument(command_prefix + _MX_FLAG,
                        '-x',
                        default=argparse.SUPPRESS,
                        action='store_true',
                        help='Set the specified host as MX (mail) host for '
                             'the specified domain.')

  if _WILDCARD_FLAG in enable_flag_by_provider[provider]:
    exclusive = client.add_mutually_exclusive_group()
    exclusive.add_argument(command_prefix + _WILDCARD_FLAG,
                           '-w',
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='ON',
                           help='Set the specified host as wildcard host for '
                                'the specified domain.')
    exclusive.add_argument(command_prefix + no_prefix + _WILDCARD_FLAG,
                           '-W',
                           dest=_WILDCARD_FLAG,
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='OFF',
                           help='Set the specified host as wildcard host for '
                                'the specified domain.')

  if _BACK_MX_FLAG in enable_flag_by_provider[provider]:
    exclusive = client.add_mutually_exclusive_group()
    exclusive.add_argument(command_prefix + _BACK_MX_FLAG,
                           '-b',
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='YES',
                           help='Set a vendor dependent backup MX (mail) host '
                                'for this hostname')
    exclusive.add_argument(command_prefix + no_prefix + _BACK_MX_FLAG,
                           '-B',
                           dest=_BACK_MX_FLAG,
                           default=argparse.SUPPRESS,
                           action='store_const',
                           const='NO',
                           help='Delete the vendor dependent backup MX (mail) '
                                'host for this hostname')

  return parser

def _Main():
  """Read dictionary, invoke process to print entries randomly."""
  parser = _BuildCommandLineParser(sys.argv[1:])
  options = parser.parse_args()
  print vars(options)

if __name__ == '__main__':
  _Main()
