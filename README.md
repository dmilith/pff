# PFF - PF-Filter. Designed for FreeBSD, OpenBSD and MacOS

## Author:
* Daniel (dmilith) Dettlaff (@dmilith)


## About:
This is a cli application that parses Nginx access.log (and FreeBSD formatted /var/log/messages) for unwanted regexp patterns, which are later added to the blocked list of PF firewall.


## Features:
* Precompiled, configurable Regexps (wanted and unwanted)
* Configurable buffer (if 0 then whole access.log is parsed each run, if specified will determine of how much of the log tail gets parsed)
* Follows simple rule, that if access.log line is matching the "wanted" regexp it's not checked further, when is matching "unwanted" regexp it's considered malicious and will be added to the firewall block


## Shell environment variables

# Increase log verbosity:

```bash
LOG=debug cargo run
```


## Configuration:

If no configuration is found in default paths, the local "pff.conf" will be created with default configuration. The file is stored in the [RON](https://github.com/ron-rs/ron) format.

Example, default configuration:

```ron
(
    access_log: "/Services/Nginx/logs/access.log",
    system_log: "/var/log/messages",
    spammers_file: "/etc/spammers",
    buffer: 16777216,
    wanted: "(\\.tgz|\\.ttf|\\.bz2|\\.gz|\\.xz|\\.zfsx|\\.zfsp|/robots\\.txt|/security\\.txt|favicon\\.ico|\\.m[4kop][34av]|sitemap.xml|/.well-known|\\.svg|verknowsys|\\.wasm|[[:alnum:]]{32}\\.p[dn][fg]|192\\.168\\.\\d{1,3}\\.\\d{1,3}|127\\.0\\.0\\.1|10\\.0\\.0\\.d{1,3})",
    unwanted: "(\\.php|\\.lua|XDEBUG|config\\.|login\\.|\\.DS_Store|mifs|\\.axd|wp-*|\\.aws|\\.[axy]ml|\\.[aj]sp+|microsoft|\\.env|\\\\x\\d+|\\.cgi|cgi-bin|HNAP1|formLogin|owa/auth/x|/dev|/tmp|/var/tmp|PAM: Authentication error for illegal user)",
)
```


## Installation details:

1. Pff assumes that the /etc/pf.conf contains the block list like this:

```conf
table <blocked> persist file "/etc/spammers"
block drop in quick from <blocked>
block drop out quick to <blocked>
```

2. Pff assumes that /etc/spammers is writable and user is root. On MacOS sudo is used to reload PF as a regular user.

3. `cargo install pff --locked` to install. On Sofin-enabled systems, just do: `s i pff`.


## License:
* Released under the [BSD](http://opensource.org/licenses/BSD-2-Clause) license.
