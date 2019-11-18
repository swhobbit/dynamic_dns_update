# dbns_update.py - Client for IPv4 Dynamic DNS updates 
## Introduction 

This program updates a dynamic DNS service to provide an IPv4 address for a   publicly accessible host which has its IP address assigned by DHCP or dynamic method.

See https://en.wikipedia.org/wiki/Dynamic_DN for an overview of dynamic DNS services.

Supports EasyDNS, Google, Hurricane Electric's Tunnelbroker.net, and various
other providers.

Specifically designed to support a host with both IPv4 and IPv6 support; it avoids reporting IPv6 addresses to the server.

## Program Requirements

This program requires Python 3.7.

The program requires no special client privileges aside from outbound network access. All privileged operations (updating of the IPv4 address) are performed on the server controlled by authentication information (user and password) sent to it.

## Command Line Help

For complete command line help run the program withe the `--help` parameter:

    dns_update.py --help flag

## Quick Start

The command in its basic form will connect to a supporting service and update the specified host name with an IP address as determined below. For example:

    dns_update.py \
      --provider google \
      --password ppppp  \
      --username uuuuu  \
      --hostname example.rscs.site

would determine current public DNS IPv4 address for the client and the current actual IPv4 address for the client.  If the two addresses differ, the program would then update the Google domain service for the specified host with the current IPv4 address.

    dns_update.py \
      --provider google \
      --password ppppp  \
      --username uuuuu  \
      --hostname victoria.rscs.site \
      --save example.conf

would write the configuration data to the file example.conf and exit.

    dns_update.py -i 120 example.conf second.cond

would load the existing configuration files `example.conf` and `second.conf` and perform the processing to check and if required update the IPv4 addresses of the hosts in each configuration file in DNS every 120 seconds.

## How It Works:

### Parameters

The program accepts parameters including:

- An update URL to connect to
- Hostname to update
- Username and password to authenticate with
- **One** of optional additional parameters to control the update:
  - A flag to take the host offline.
  - A specific IP address to update to 
  - A URL to query the client current public IP address via

### Basic Processing

The program default processing is as follows:
- Command line arguments are processed
- If possible, the current client address is determined from the provided
source (fixed parameter or by contacting the query URL)
- The hostname is queried in DNS for the current address
- If the client address is not known or does not match the address in DNS,
the update URL is invoked with the provided username, password, hostname and
(if available) the current client address.

### Advanced Processing

The program has other modes which extend the basic processing:
- The program can process the command line arguments and save them in a file
for later retrieval and use. In the this mode (invoked by the --save
flag), no update is performed.
- The program can load the arguments previously written to one or more files
by the --save option. If multiple files are loaded, each configuration is
processed in order. This allows for example, both updating a DNS entry at
one provider and updating an IPV6 tunnel endpoint at a second provider.
- When one or more configuration files are used, the program be specified
to run in polling mode, where rather than exiting after a single pass, it
sleeps for a configured period and then processing all loaded
configurations again.

#### Processing Notes

The program is written to both minimize update server load and handle some unique edge cases:

- The query of the client IP address is always forced to use IPv4; this
avoids problems with providers (such as Google) which prefer IPv6
connections.
- By doing a simple anonymous query for the public IP address and comparing
it to the current DNS address of the hostname, the server update is
avoided completely if the address has not changed.
- In some cases, the hostname has no published IPV4 address in DNS (example: when
providing an IPv6 tunnel end point) or it may wrong (example:
when the updated URL is the not live DNS provider.  In such cases:
   * The check of the hostname in DNS can be disabled.
   * When in polling mode, the updated record's IP address can be cached in memory to avoid duplicate updates.

## Other References
- https://support.easydns.com/tutorials/dynamicUpdateSpecs.php
- https://support.google.com/domains/answer/6147083?hl=en
- https://forums.he.net/index.php?topic=1994.0
