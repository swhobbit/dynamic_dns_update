#!/usr/bin/python
# encoding: utf-8
'''
dns_update

This program generates updates to the Google Dynamic DNS service
(https://support.google.com/domains/answer/6147083).
'''

__author__ = 'ahd@kew.com (Drew Derbyshire)'

import base64
import getopt
import pickle
import re
import socket
import sys
import syslog
import time
import urllib2

HOSTNAME_URL_REGEXP = re.compile("https://([^/]+)/.+", re.IGNORECASE)

class Usage(Exception):
  """Error thrown for bad command line arguments."""

  def __init__(self, msg):
    super(Usage, self).__init__()
    self.msg = msg


class Option(object):
  """Defines single option, including its short/long flags and value."""

  # Manifest constants for the flag names used in multiple places.
  CONFIGURATION_FILE = 'file'
  DELAY_INTERVAL_MINUTES = 'delay_interval_minutes'
  HELP = 'help'
  HOSTNAME = 'hostname'
  MYIP = 'MYIP'
  OFFLINE = 'offline'
  PASSWORD = 'password'
  SAVE = 'save'
  URL = 'url'
  USERNAME = 'username'

  def __init__(self, name, default_value,
               is_persistent=True, is_url_parameter=True, is_required=True,
               conflicting_flags=None, required_flags=None, boolean_values=None):
    """Create a new Option instance."""
    self.name = name
    self.value = default_value
    self.is_url_parameter = is_url_parameter
    self.is_boolean = isinstance(default_value, bool)

    # boolean flags always have a usable default, and are never persistent.
    self.is_persistent = is_persistent and not self.is_boolean
    self.is_required = is_required and not self.is_boolean

    self._required_flags = required_flags or []
    self._conflicting_flags = conflicting_flags or []
    self._boolean_values = boolean_values


  def GetFlagName(self):
    """Returns the command line flag with value character used by getopt."""
    if self.is_boolean:
      return self.name
    else:
      return self.name + '='

  def Get(self):
    """Return the current option as a URL parameter."""
    if self.is_boolean and self._boolean_values:
      return '{}={}'.format(self.name, self._boolean_values[self.value])
    elif self.is_boolean and self.value:
      return self.name
    elif self.value:
      return '{}={}'.format(self.name, self.value)
    else:
      return None

  def VerifyFlagInteraction(self, options):
    """Verifies interaction of other flags specified on the same invocation.

    Raises:
      Usage exception if conflicting options are specified or required options
      are missing.
    """
    # If not specified, verify the flag not existing is acceptable.
    if not self.value:
      if self.is_required:
        raise Usage('Required parameter missing: ' + self.name)
      return

    # Check for any conflicting flags being present.
    for possible_conflict in self._conflicting_flags:
      if options[possible_conflict].value:
        raise Usage("Conflicting options --{} and --{} both specified.".
                    format(self.name, possible_conflict))

    # Check for flags needed by current flag are also specified.
    for dependency in self._required_flags:
      if not options[dependency].value:
        raise Usage("Option --{} requires that --{} also be specified.".
                    format(self.name, dependency))

  def __str__(self):
    keys = ['value',
            'is_boolean',
            'is_persistent',
            'is_required',
            'is_url_parameter']
    properties = ', '.join(['{}: {}'.format(k, str(self.__getattribute__(k)))
                            for k in keys
                            if self.__getattribute__(k) is not False])
    return '{}: {}, flags: --{}'.format(self.name,
                                        properties,
                                        self.GetFlagName())


def _Log(level, message):
  """Wrapper for logging messages via syslog at the specified level."""
  syslog.syslog(level, message)


def _InitializeOptionDictionary():
  """Builds a collection of value command line options."""
  options = {}
  for option in (
      Option(Option.DELAY_INTERVAL_MINUTES, None,
             is_required=False, is_persistent=False, is_url_parameter=False,
             conflicting_flags=(Option.PASSWORD,
                                Option.USERNAME,
                                Option.SAVE,
                                Option.MYIP,
                                Option.OFFLINE),
             required_flags=(Option.CONFIGURATION_FILE,)),
      Option(Option.HELP, False),
      Option(Option.HOSTNAME, None),
      Option(Option.CONFIGURATION_FILE, None,
             is_required=False, is_persistent=False, is_url_parameter=False),
      Option(Option.MYIP, None,
             is_required=False, is_persistent=False,
             conflicting_flags=(Option.OFFLINE, Option.SAVE)),
      Option(Option.OFFLINE, False, boolean_values=("no", "yes")),
      Option(Option.PASSWORD, None, is_url_parameter=False),
      Option(Option.SAVE, False,
             conflicting_flags=(Option.OFFLINE, Option.MYIP),
             required_flags=(Option.PASSWORD,
                             Option.HOSTNAME,
                             Option.URL,
                             Option.CONFIGURATION_FILE)),
      Option(Option.URL, 'https://domains.google.com/nic/update',
             is_url_parameter=False),
      Option(Option.USERNAME, None, is_url_parameter=False),
      ):
    options[option.name] = option
  return options


def _GetPersistentOptions(options):
  """Return list of non-empty/True persistent options associated with flags."""
  collected = set()
  result = []
  for option in options.values():
    if option.value and option.is_persistent and option.name not in collected:
      collected.add(option.name)
      result.append(option)
  return result


def _PrintHelp(options):
  """Prints program help."""
  print >> sys.stderr, 'Usage:', sys.argv[0],
  for _, option in sorted(options.items()):
    text = '[--{}{}]'.format(option.GetFlagName(),
                             ['value', ''][option.is_boolean])
    print >> sys.stderr, text,
  print >> sys.stderr, ''


def _SaveOptions(options):
  """Write options out to a file."""
  configuration_file = options[Option.CONFIGURATION_FILE].value
  with open(configuration_file, 'w') as handle:
    writable_flags = _GetPersistentOptions(options)
    pickled = pickle.dumps(writable_flags, pickle.HIGHEST_PROTOCOL)
    handle.write(base64.b32encode(pickled))


def _LoadOptions(options):
  """Load saved options from a file; never overrides options already set."""
  configuration_file = options[Option.CONFIGURATION_FILE].value
  with open(configuration_file, 'r') as handle:
    loaded_flags = pickle.loads(base64.b32decode(handle.read()))
  for option in loaded_flags:
    if not options[option.name].value:
      options[option.name].value = option.value


def _RemoteUpdate(options):
  """Perform the remote update."""
  # Extract the hostname from our URL and replace it with the IP v4 address
  # of it. This insures we connect via IP V4, which is the only address
  # family Google and most other dynamic DNS services support.
  hostname = HOSTNAME_URL_REGEXP.search(options[Option.URL].value).group(1)
  if not hostname:
    raise Usage("Could not parse server host name from URL: "
                + options[Option.URL].value)
  try:
    ip_address = socket.gethostbyname(hostname)
  except socket.gaierror, ex:
    _Log(syslog.LOG_WARNING,
         "Could not look up adress for {}: {}".format(hostname, ex))
  url_with_address = options[Option.URL].value.replace(hostname, ip_address)

  url_parameters = '&'.join([option.Get() for option in options.values()
                             if option.value and option.is_url_parameter])
  full_url = '{}?{}'.format(options[Option.URL].value, url_parameters)
  full_url_with_address = '{}?{}'.format(url_with_address, url_parameters)

  # Following code based on stackoverflow.com example athttp://goo.gl/WJldUm
  passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
  passman.add_password(None,
                       url_with_address,
                       options[Option.USERNAME].value,
                       options[Option.PASSWORD].value)
  # because we have put None at the start it will always
  # use this username/password combination for  urls
  # for which `url` is a super-url

  authhandler = urllib2.HTTPBasicAuthHandler(passman)
  opener = urllib2.build_opener(authhandler)
  urllib2.install_opener(opener)
  # All calls to urllib2.urlopen will now use our handler
  # Make sure not to include the protocol in with the URL, or
  # HTTPPasswordMgrWithDefaultRealm will be very confused.
  # You must (of course) use it when fetching the page though.

  try:
    # We override the host name in the headers because the default header
    # would have the IP v4 address, which is useless to a virtual host.
    request = urllib2.Request(full_url_with_address, headers={'Host': hostname})
    handle = urllib2.urlopen(request)
    _Log(syslog.LOG_INFO,
         'Processed {} (server address {}) with HTTP return code {}'.
         format(full_url, ip_address, handle.getcode()))
    for line in handle:
      if line.strip():
        _Log(syslog.LOG_INFO, line.strip())
    # authentication is now handled automatically for us
  except (urllib2.HTTPError, urllib2.URLError), e:
    _Log(syslog.LOG_WARNING, 'Error processing {}: {}'.format(full_url, e))


def _DaemonMode(options):
  """Invoke the remote update on a regular basis."""
  while True:
    time.sleep(options[Option.DELAY_INTERVAL_MINUTES].value * 60)
    _RemoteUpdate(options)


def _ProcessOptions(argv, options):
  """Parse command line flags, including early trigger of help if requested."""
  long_flags = [option.GetFlagName() for option in options.values()]
  try:
    opts, trailing_args = getopt.getopt(argv[1:], '', long_flags)
  except getopt.error, msg:
    raise Usage(msg)

  if trailing_args:
    raise Usage('Unwanted positional arguments specified: ' +
                ' '.join(trailing_args))
  # Assign value
  for opt, value in opts:
    option = options[opt.lstrip('-')]
    if option.is_boolean:
      option.value = not option.value
    else:
      option.value = value

  if options[Option.HELP].value:
    raise Usage('Help requested.')


def Main(argv=None):
  """Command line entry point to request DNS update."""
  syslog.openlog(
      sys.argv[0].rpartition('/')[2],
      logoption=syslog.LOG_PID | syslog.LOG_CONS | syslog.LOG_PERROR,
      facility=syslog.LOG_DAEMON)

  options = _InitializeOptionDictionary()

  try:
    _ProcessOptions(argv or sys.argv, options)

    # We're careful to load options BEFORE validating the flags (since some
    # required options may need to be loaded first), but save AFTER validating
    # the flags (so we don't save incomplete flags).
    if (options[Option.CONFIGURATION_FILE].value
        and not options[Option.SAVE].value):
      _LoadOptions(options)

    for option in options.values():
      option.VerifyFlagInteraction(options)

    if options[Option.SAVE].value:
      # Save persistent data and exit without actually updating.
      _SaveOptions(options)
    elif options[Option.DELAY_INTERVAL_MINUTES].value:
      _DaemonMode(options)
    else:
      # One shot update.
      _RemoteUpdate(options)
  except Usage, err:
    _Log(syslog.LOG_WARNING, str(err.msg))
    _PrintHelp(options)
    return


if __name__ == '__main__':
  sys.exit(Main())
