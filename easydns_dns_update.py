#!/usr/bin/python
# encoding: utf-8
'''
dns_update

Copyright (c) 2013 by Kendra Electronic Wonderworks. All rights reserved.
'''

__author__ = 'ahd@kew.com (Drew Derbyshire)'

import getopt
import pickle
import os
import sys
import syslog
import time
import urllib2

_PASSWORD_FLAG = 'password'
_CONFIGURATION_FILE_FLAG = 'file'
_HELP_FLAG = 'help'
_HOSTNAME_FLAG = 'hostname'
_DELAY_INTERVAL_FLAG = 'delay_interval'
_SAVE_FLAG = 'save'
_TLD_FLAG = 'tld'
_URL_FLAG = 'url'
_USERNAME_FLAG = 'username'


HELP_MESSAGE = '''
This program generates updates to a dynamic DNS server, such as
EasyDNS (http://support.easydns.com/tutorials/dynamicUpdateSpecs.php).
'''


class Usage(Exception):
  """Error thrown for bad command line arguments."""

  def __init__(self, msg):
    self.msg = msg


class Option(object):
  """Defines single option, including its short/long flags and value."""

  def __init__(self, name, default_value, is_persistent=True, is_required=True,
               url_parameter=True, boolean_values=None):
    """Create a new Option instance."""
    self.name = name
    self.value = default_value
    self._short_flag = name[0]
    self.is_persistent = is_persistent
    self._boolean_values = boolean_values
    self.is_boolean = isinstance(default_value, bool)
    # Internal parameters are never a parameter to the remote host.
    self.url_parameter = url_parameter and is_persistent
    # Internal parameters are never required to execute the command
    self.is_required = is_required and is_persistent and not self.is_boolean

  def SetShortFLag(self, short_flags):
    """Updates and return short command line flag with value char."""
    if self._short_flag in short_flags:
      self._short_flag = self._short_flag.upper()
    if self.is_boolean:
      return self._short_flag
    else:
      return self._short_flag + ':'

  def GetLongFlag(self):
    """Returns the long command line flag with value char."""
    if self.is_boolean:
      return self.name
    else:
      return self.name + '='

  def GetFlagKeys(self):
    """Reports flag values without optional trailing value character."""
    return ( '-' + self._short_flag, '--' + self.name)

  def Get(self):
    """Return the current option as URL a parameter."""
    if self.is_boolean and self._boolean_values:
      return '%s=%s' % (self.name, self._boolean_values[self.value])
    elif self.is_boolean and self.value:
      return self.name
    elif self.value:
      return '%s=%s' % (self.name, self.value)
    else:
      return None

  def __str__(self):
    keys = ['value',
            'is_boolean',
            'is_persistent',
            'is_required',
            'url_parameter']
    properties = ', '.join(['%s: %s' % (k, str(self.__getattribute__(k)))
                   for k in keys if self.__getattribute__(k) is not False])
    return '%s: %s, flags: -%s and --%s' % (self.name,
                                            properties,
                                            self.SetShortFLag(''),
                                            self.GetLongFlag())

def _Log(level, message):
  print message
  syslog.syslog(level, message)

def _AssembleOptions():
  """Builds a collection of value command line options."""
  options = {}
  for option in (
      Option('backmx', False, boolean_values=('NO', 'YES')),
      Option(_DELAY_INTERVAL_FLAG, None, is_persistent=False),
      Option(_HELP_FLAG, False, is_persistent=False),
      Option(_HOSTNAME_FLAG, None),
      Option(_CONFIGURATION_FILE_FLAG, None, is_persistent=False),
      Option('myip', '1.1.1.1'),
      Option('mx', None, is_required=False),
      Option(_PASSWORD_FLAG, None, url_parameter=False),
      Option(_SAVE_FLAG, False, is_persistent=False),
      Option(_TLD_FLAG, None, is_required=False),
      Option(_URL_FLAG, 'https://members.easydns.com/dyn/dyndns.php',
             url_parameter=False),
      Option(_USERNAME_FLAG, None, url_parameter=False),
      Option('wildcard', False, boolean_values=('OFF', 'ON')),
      Option('verbose', False, is_persistent=False)
    ):
    options[option.name] = option
  return options


def _GetOptionFlags(options):
  """Returns tuple of short string and long list for getopt."""
  short_flags = ''
  long_flags = []
  for option in options.values():
    short_flags += option.SetShortFLag(short_flags)
    long_flags += [option.GetLongFlag()]
  return short_flags, long_flags

def _GetExternalOptions(options):
  """Return list of non-empty/True external options associated with flags."""
  collected = set()
  result = []
  for option in options.values():
    if option.value and option.is_persistent and option.name not in collected:
      collected.add(option.name)
      result.append(option)
  return result

def _GetFlagMap(options):
  """Returns map of options with CLI flags and canonical option name as keys."""
  flag_map = {}
  for option in options.values():
    for key in option.GetFlagKeys():
      flag_map[key] = option
  return flag_map

def _CheckExclusive(options, primary_flag, *conflicting_flags):
  """Reports if the primary and any conflicted options are specified."""
  if not options[primary_flag].value:
    return
  for possible_conflict in conflicting_flags:
    if options[possible_conflict].value:
      raise Usage("Conflicting options --%s and --%s both specified." %
                  (primary_flag, possible_conflict))

def _CheckRequired(options, primary_flag, *dependency_flags):
  """Reports if the primary is missing required supporting flags."""
  if not options[primary_flag].value:
    return
  for depencency in dependency_flags:
    if not options[depencency].value:
      raise Usage("Option --%s requires that --%s also be specified." %
                  (primary_flag, depencency))

def _PrintHelp(options):
  """Prints program help."""
  print >> sys.stderr, HELP_MESSAGE
  print >> sys.stderr, 'Usage: ', sys.argv[0] ,
  for _, option in sorted(options.items()):
    flags = option.GetFlagKeys()
    if option.is_boolean:
      print >> sys.stderr, '[%s|%s] ' % flags,
    else:
      print >> sys.stderr, '[%s value|%s=value] ' % flags,
  print >> sys.stderr , ''

def _SaveOptions(options):
  """Write options out to a file."""
  configuration_file = options[_CONFIGURATION_FILE_FLAG].value
  handle = open(configuration_file, 'w')
  try:
    writable_options = _GetExternalOptions(options)
    pickle.dump(writable_options, handle)
  finally:
    handle.close()

def _LoadOptions(options):
  """Load saved options from a file."""
  configuration_file = options[_CONFIGURATION_FILE_FLAG].value
  handle = open(configuration_file, 'r')
  try:
    loaded_options = pickle.load(handle)
  finally:
    handle.close()
  for option in loaded_options:
    if not options[option.name].value:
      options[option.name].value = option.value

def _RemoteUpdate(options):
  """Perform the remote update."""
  for _, option in sorted(options.items()):
    if option.is_required and not option.value:
      raise Usage('Required parameter missing: ' + option.name)

  parameters = '&'.join([option.Get() for option in options.values()
                        if option.value and option.url_parameter])

  full_url = '%s?%s' % (options[_URL_FLAG].value, parameters)
  password = options[_PASSWORD_FLAG].value
  username = options[_USERNAME_FLAG].value
  # Follow code is from stackoverflow.com, see http://goo.gl/WJldUm
  passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
  passman.add_password(None, options[_URL_FLAG].value, username, password)
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
    handle = urllib2.urlopen(full_url)
    _Log(syslog.LOG_INFO, 'Processed %s with HTTP return code %s' %
                  (full_url, handle.getcode()))
    for line in handle:
      if line.strip():
        _Log(syslog.LOG_INFO, line.strip())
    # authentication is now handled automatically for us
  except (urllib2.HTTPError, urllib2.URLError), e:
    syslog.syslog(syslog.LOG_WARNING, 'Error processing %s: %s' % (full_url, e))

def _DaemonMode(options):
  """Invoke the remote update on a regular basis."""
  while True:
    time.sleep(options[_DELAY_INTERVAL_FLAG].value)
    _RemoteUpdate(options)

def Main(argv=None):
  """Command line entry point to request DNS update."""
  if argv is None:
    argv = sys.argv

  options = _AssembleOptions()
  short_flags, long_flags = _GetOptionFlags(options)

  try:
    try:
      opts, trailing_args = getopt.getopt(argv[1:], short_flags,
                                          long_flags)
    except getopt.error, msg:
      raise Usage(msg)

    if trailing_args:
      raise Usage('Unwanted positional arguments specified: ' +
                  ' '.join(trailing_args))
    # option processing
    flag_map = _GetFlagMap(options)
    for option, value in opts:
      if flag_map[option].is_boolean:
        flag_map[option].value = not flag_map[option].value
      else:
        flag_map[option].value = value

    if options[_HELP_FLAG].value:
      raise Usage('Help requested.')

    # Do not allow password on command line when program will run as
    # daemon
    _CheckExclusive(options, _DELAY_INTERVAL_FLAG, _PASSWORD_FLAG)
    # Require file and other parameters when saving, and require file
    # when looping.
    _CheckRequired(options,
                   _SAVE_FLAG,
                   _PASSWORD_FLAG,
                   _HOSTNAME_FLAG,
                   _CONFIGURATION_FILE_FLAG)
    _CheckRequired(options,
                   _DELAY_INTERVAL_FLAG,
                   _CONFIGURATION_FILE_FLAG)

    if options[_SAVE_FLAG].value:
      _SaveOptions(options)
      return

    if options[_CONFIGURATION_FILE_FLAG].value:
      _LoadOptions(options)

    if options[_DELAY_INTERVAL_FLAG].value:
      _DaemonMode(options)
    else:
      _RemoteUpdate(options)
  except Usage, err:
    print >> sys.stderr, '%s: %s' % (sys.argv[0].split('/')[-1],
                                     str(err.msg))
    _PrintHelp(options)
    return

if __name__ == '__main__':
  syslog.openlog(sys.argv[0].rpartition('/')[2],
                 logoption=syslog.LOG_PID | syslog.LOG_CONS,
                 facility=syslog.LOG_DAEMON)
  sys.exit(Main())
