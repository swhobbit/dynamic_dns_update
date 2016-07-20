usage: dns_update.py [-h] [--version]
                     [--provider {easydns,extended,google,simple,tunnelbroker}]
                     [--poll_interval_seconds SECONDS] --username USERNAME
                     --password PASSWORD --update_url URL
                     [--check_provider_address | --no_check_provider_address]
                     [--cache_provider_address_seconds SECONDS] --hostname
                     HOSTNAME [--myip MYIP | --offline]
                     [--query_url URL | --no_query_url] [--save OUTPUT-FILE]
                     [FILE [FILE ...]]

Dynamic DNS client

optional arguments:
  -h, --help            show this help message and exit

General:
  General Program flags

  --version, -v         Print the program version
  --provider {easydns,extended,google,simple,tunnelbroker}, -P {easydns,extended,google,simple,tunnelbroker}
                        Provide defaults (such as the server update URL) and
                        set restrictions consistent with the specified
                        provider
  --poll_interval_seconds SECONDS, -i SECONDS
                        Interval in seconds to poll for changes to the client
                        IP address. Default is not to poll, but instead exit
                        after performing processing once. Note that a password
                        cannot be specified on the command line when using
                        this flag; it be must loaded from a configuration file
                        written with the --save flag instead.

Provider:
  DNS Service provider flags

  --username USERNAME, -U USERNAME
                        User name to authenicate as on provider server
  --password PASSWORD, -p PASSWORD
                        Password/authorization token on provider server
  --update_url URL, -u URL
                        DNS service provider web address for IP address
                        updates. Default for provider "simple" is None
  --check_provider_address, -k
                        Check the current address reported for the hostname
                        (specified by --hostname by DNS, and skip updating the
                        provider if the address reported by DNS is correct
  --no_check_provider_address, -K
                        Do not check the current client address set at the
                        provider when polling.
  --cache_provider_address_seconds SECONDS, -c SECONDS
                        When polling via the --poll_interval_seconds flag,
                        remember the address currently set at the provider for
                        the specified number of seconds, and do not attempt to
                        update the provider if the current client public
                        address still matches it during this period.

Client:
  Client specification flags

  --hostname HOSTNAME, -H HOSTNAME
                        Name of dynamic jost to update
  --myip MYIP, -m MYIP  Dynamic IP address to assign to host; default is query
                        the URL specified by --query_url using IPv4.
  --offline, -o         Set this host to a provider dependent offline status
  --query_url URL, -q URL
                        URL which returns the current IPv4 address of the
                        client. The default query URL is
                        https://domains.google.com/checkip
  --no_query_url, -Q    Do not query the current address of the host before
                        updating

Persistance:
  File save/load flags

  --save OUTPUT-FILE, -s OUTPUT-FILE
                        Name of a configuration file to write for later use.
                        The file must not exist. When this flag is specified,
                        the file is only written; no server update is
                        performed.
  FILE                  Load configuration file(s) previously written with the
                        --save flag and process the provider defined in each.
                        The use of saved configuration files is the only way
                        to have the program process more than one update per
                        invocation.

The above listed flags are valid for provider "simple". For the flags valid
for another provider, specifiy the --provider flag with the --help flag on the
command line.
