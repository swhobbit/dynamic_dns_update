Help on module dns_update:

NAME
    dns_update

FILE
    /Users/ahd/src/dynamic_dns_update/dns_update.py

DESCRIPTION
    Client for IPv4 Dynamic DNS updates; see
    (https://en.wikipedia.org/wiki/Dynamic_DNS#DDNS_for_Internet_access_devices).
    Supports EasyDNS, Google, Hurricane Electrics's Tunnelbroker.net, and various
    other providers.
    
    For command line help:
      Run the program with the --help flag
    
    How it works:
    
      Given the parameters of:
        - an update URL to connect to
        - hostname to update
        - username and password to authicate with
      and optionally additional parameters:
        - a specific IP address to update to -OR-
        - a URL to query the client current public IP address
    
      The program default processing is as follows:
        - Command line arguments are processed
        - If possible, the current client address is determined from the provided
          source (fixed parameter or by contacting the query URL)
        - The hostname is queried in DNS for the current address
        - If the client address does not known or does not match the address in DNS
          the update URL is invoked with the username, password, hostname and
          (if available) the current client address.
    
      The program has other modes which extend the basic processing:
        - The program can process the command line arguments and save them in a file
          for later retrieval and use. In the this mode (invoked by the --save
          flag), no update is performed.
        - The program can load the arguments previously written to one or more files
          by the --save option. If multiple files are loaded, each configuration is
          processed in order. This allows for example both updating a DNS entry at
          one provider and updating an IPV6 tunnel endpoint at a second provider.
        - When one or more configuration files are used, the program be specified
          to run in polling mode, where rather than exiting after a single pass,
          sleeps for a configured period and then processing all loaded
          configurations again.
    
      It should be noted that the program is written to both minimize update server
      load and handle some unique edge cases:
        - The query of the client IP address is always forced to use IPv4; this
          avoid problems with providers (such as Google) which provide IPv6
          connections by default.
        - By doing a simple anonymous query for the public IP address and comparing
          it to the current DNS address of the hostname, the server update is
          avoided completely if the address has not changed.
        - In some cases, the hostname has no IPV4 address in DNS (example: when
          providing an IPv6 tunnel end point) or it may wrong (example:
          when the updated URL is the not live DNS provider.  In such cases:
          * the check of the hostname in DNS can be disabled.
          * When in polling mode, the updated record's IP address can be cached in
            memory to avoid duplicate updates.
    
        Other references:
          https://support.easydns.com/tutorials/dynamicUpdateSpecs.php
          https://support.google.com/domains/answer/6147083?hl=en
          https://forums.he.net/index.php?topic=1994.0
    
        This program requires Python 2.7.

CLASSES
    __builtin__.object
        Provider
    
    class Provider(__builtin__.object)
     |  Holder for provider specific metadata.
     |  
     |  Methods defined here:
     |  
     |  __init__(self, name, update_url=None, query_url='https://domains.google.com/checkip', enabled_flags=None, cache_provider_address_seconds=0, check_provider_address=True)
     |  
     |  ----------------------------------------------------------------------
     |  Data descriptors defined here:
     |  
     |  __dict__
     |      dictionary for instance variables (if defined)
     |  
     |  __weakref__
     |      list of weak references to the object (if defined)
     |  
     |  ----------------------------------------------------------------------
     |  Data and other attributes defined here:
     |  
     |  generic_optional_flags = frozenset(['backmx', 'mx', 'tld', 'wildcard']...

DATA
    __author__ = 'Kendra Electronic Wonderworks (uupc-help@kew.com)'
    __version__ = '0.9.4'

VERSION
    0.9.4

AUTHOR
    Kendra Electronic Wonderworks (uupc-help@kew.com)


