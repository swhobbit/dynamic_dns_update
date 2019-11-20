# dns_update.py - Client For IPv4 Dynamic DNS Updates
## Introduction

`dns_update.py` is a client updates a dynamic DNS service to provide an IPv4 address for a   publicly accessible host which has its IPv4 address assigned by DHCP or dynamic method.

See https://en.wikipedia.org/wiki/Dynamic_DNS for an overview of dynamic DNS services.

The program supports:
- EasyDNS,
- Google Domains,
- Hurricane Electric's Tunnelbroker.net,

and various other providers.

Specifically designed to running on a host with both IPv4 and IPv6 support; it avoids reporting IPv6 addresses to the server.

## Program Requirements

`dns_update.py` requires Python 3.7.

The program requires no special client privileges aside from outbound network access. All privileged operations (updating of the IPv4 address) are performed on the server controlled by the authentication information (user and password) sent to it.

## Command Line Help

For complete command line help, run the program with the `--help` parameter:

    dns_update.py --help

## Quick Start

### Basic Operation

In its default processing mode, `dns_update.py` updates the specified host name with a new IPv4 address if required. For example:

    dns_update.py \
      --provider google \
      --password ppppp  \
      --username uuuuu  \
      --hostname example.rscs.site

would first determine current public DNS IPv4 address for the client and the current actual IPv4 address for the client. If the two addresses differ,the program would then update the Google domain service for the specified host with the current IPv4 address.

### Saving and Loading Configuration Parameters

`dns_update.py` can also write the configuration to disk:

    dns_update.py \
      --provider google \
      --password ppppp  \
      --username uuuuu  \
      --hostname example.rscs.site \
      --save example.conf

would write the configuration data to the file example.conf and exit.

Then the parameters can be loaded from the file:

    dns_update.py -i 120 example.conf second.conf

would load the existing configuration files `example.conf` and `second.conf` and perform the processing to check and if required update the IPv4 addresses of the hosts in each configuration file in DNS every 120 seconds.

## In More Detail

### Parameters

`dns_update.py` accepts parameters controlling the host update including:

- An update URL to connect to
- Hostname to update
- Username and password to authenticate with
- Optionally, **one** additional parameter to:
  - Suppress looking up public IPv4 of the client host (deferring the lookup to the server)
  - Take the host offline.
  - Specify the IPv4 address to update to
  - A URL to use to query the client current public IPv4 address

### Basic Processing

`dns_update.py` default processing is as follows:
- Command line arguments are processed
- If possible, the current client address is determined from the provided
source (by contacting a server or via a fixed parameter)
- The hostname is queried in DNS for the current address
- If the client address is not known or does not match the address in DNS,
the update URL is invoked with the provided username, password, hostname and
(if available) the current client address.

### Advanced Processing

`dns_update.py` has other modes which extend the basic processing:
- The program can process the command line arguments and save them in a file
for later retrieval and use. In the this mode (invoked by the --save
flag), no update is performed.
- The program can load the arguments previously written to one or more files
by the `--save` option. If multiple files are loaded, each configuration is
processed in order. This allows for example, one invocation of the program both updating a DNS entry at one provider and updating an IPV6 tunnel endpoint at a second provider.
- When one or more configuration files are used, `dns_update.py` may be specified to run in polling mode.  In this mode, rather than exiting after a single pass, the program sleeps for a configured period and then processes the loaded configurations again.

#### Processing Notes

`dns_update.py` is written to both minimize update server load and handle some unique edge cases:

- The client polling interval should be longer than the TTL (time to live) value for the host in DNS. Otherwise, the updated IPv4 address will not be visible for at least one update cycle and a redundant update will occur.
- By doing a simple anonymous query for the public IPv4 address and comparing
it to the current DNS address of the hostname, the server update is
avoided completely if the address has not changed. (It does query a server to determine the public IPv4 address of the client.)
- In some cases, the hostname has no published IPV4 address in DNS (example: when providing an IPv6 tunnel end point) or it may be wrong (example: when the updated URL is the not live DNS provider. In such cases:
   * The check of the hostname in DNS can be disabled.
   * When in polling mode, the updated record's IPv4 address can be cached in memory to avoid duplicate updates.
- The query of the client public address is always forced to use IPv4; this
avoids problems with providers (such as Google) which prefer implicitly IPv6
connections.

**Warning:** If the client host running `dns_update.py` is IPv6 enabled *and* the `--no_query_url` option (suppressing explicit query of the host public IPv4 address) is specified, the server sees the client as an IPv6 host. Thus, Bad Things happen.

## Other References

Documentation on specific services:

- https://support.easydns.com/tutorials/dynamicUpdateSpecs.php
- https://support.google.com/domains/answer/6147083?hl=en
- https://forums.he.net/index.php?topic=1994.0
