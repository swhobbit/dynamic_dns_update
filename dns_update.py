#!/usr/bin/python
'''
Client for Dynamic DNS updates.  Supports EasyDNS, Google, Hurricane Electrics's
Tunnelbroker.net, and many generic services.
'''

import argparse


# Provide Server side options
_PASSWORD_FLAG = 'password'
_USERNAME_FLAG = 'username'
_PROVIDER_MODE_FLAG = 'provider'
_URL_FLAG = 'url'

# Client options
_TLD_FLAG = 'tld'
_HOSTNAME_FLAG = 'hostname'
_LOCAL_IP_FLAG = 'local_ip'
_BACK_MX_FLAG = 'backmx'
_MX_FLAG = 'mx'
_WILDCARD_FLAG = 'wildcard'

# Internal program options
_CONFIGURATION_FILE_FLAG = 'from'
_SAVE_FILE_FLAG = 'save'
_DELAY_INTERVAL_FLAG = 'delay_interval'

def _BuildCommandLineParser():
  """Build up the options for parsing the command line options.

  Returns:
    ArgumentParser with all valid (possibly conflicting options)
  """
  command_prefix = '--'
  no_prefix = 'no_'
  parser = argparse.ArgumentParser(description='Dynamic DNS client',
                                   add_help=True)
  general = parser.add_argument_group('General', 'General Program options')
  general.add_argument('--' + _PROVIDER_MODE_FLAG, '-q',
                       choices=['google', 'easydns', 'tunnelbroker'],
                       default=argparse.SUPPRESS,
                       help='Provide defaults (such as server URL) and set '
                       + 'restrictions consistent with the specified '
                       + 'provider')
  general.add_argument('--' + _DELAY_INTERVAL_FLAG, '-i',
                       type=int,
                       metavar='SECONDS',
                       default=argparse.SUPPRESS,
                       help='Interval in seconds to perform processing. '
                            'Default is exit after performing processing once')

  # Service provider optiond
  server = parser.add_argument_group('Provider', 'DNS Service provider options')
  server.add_argument(command_prefix + _PASSWORD_FLAG,
                      '-p',
                      default=argparse.SUPPRESS,
                      help='Password/authorization token for provider server')
  server.add_argument(command_prefix + _URL_FLAG,
                      '-u',
                      default=argparse.SUPPRESS,
                      help='DNS service provider web address to connect to')
  server.add_argument(command_prefix + _USERNAME_FLAG, '-U',
                      default=argparse.SUPPRESS,
                      help='User name for provider server')

  # Client configuration options
  client = parser.add_argument_group('Client', 'Client specification options')
  client.add_argument(command_prefix + _TLD_FLAG,
                      '-t',
                      default=argparse.SUPPRESS,
                      help='Top level of domain to update.')
  client.add_argument(command_prefix + _LOCAL_IP_FLAG,
                      command_prefix + 'my_ip',
                      '-l',
                      default=argparse.SUPPRESS,
                      help='Dynamic IP address to assign to host')

  client.add_argument(command_prefix + _WILDCARD_FLAG,
                      '-w',
                      default=argparse.SUPPRESS,
                      action='store_const',
                      const='ON',
                      help='Set the specified host as wildcard host for '
                           'the specified domain.')
  client.add_argument(command_prefix + no_prefix + _WILDCARD_FLAG,
                      '-W',
                      default=argparse.SUPPRESS,
                      action='store_const',
                      const='OFF',
                      help='Set the specified host as wildcard host for '
                           'the specified domain.')

  client.add_argument(command_prefix + _MX_FLAG,
                      '-x',
                      default=argparse.SUPPRESS,
                      action='store_true',
                      help='Set the specified host as MX (mail) host for '
                           'the specified domain.')

  client.add_argument(command_prefix + _BACK_MX_FLAG,
                      '-b',
                      default=argparse.SUPPRESS,
                      action='store_const',
                      const='YES',
                      help='Set a vendor dependent backup MX (mail) host for '
                           'this hostname')
  client.add_argument(command_prefix + no_prefix + _BACK_MX_FLAG,
                      '-B',
                      default=argparse.SUPPRESS,
                      action='store_const',
                      const='NO',
                      help='Delete the vendor dependent backup MX (mail) host '
                           'for this hostname')

  # File argument(s)
  program = parser.add_argument_group('Persistance', 'File save/load options')
  program.add_argument(command_prefix + _SAVE_FILE_FLAG,
                       '-s',
                       default=argparse.SUPPRESS,
                       metavar='file',
                       type=argparse.FileType('r'),
                       help='Configuration file to write for later use')
  program.add_argument(_CONFIGURATION_FILE_FLAG,  # positional!
                       default=argparse.SUPPRESS,
                       metavar='file',
                       nargs='*',
                       type=argparse.FileType('r'),
                       help='Configuration file(s)s previously written with '
                       + 'the --{} option'.format(_SAVE_FILE_FLAG))
  return parser

def _Main():
  """Read dictionary, invoke process to print entries randomly."""
  parser = _BuildCommandLineParser()
  options = parser.parse_args()
  print options.vars()

if __name__ == '__main__':
  _Main()
