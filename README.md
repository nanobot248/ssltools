# ssltools

## Table of Contents
* [INSTALLATION](#installation)
* [COMMANDS](#commands)
* [LINCENSE](#license)

## INSTALLATION
The tools requires python "jsonpath" and "jsonpointer" packages (`python-jsonpath-rw` and `python-jsonpointer` in Debian/Ubuntu) and a working `openssl` command. The `openssl`command must be available in the PATH environment variable.

**The following works in Ubuntu 16.04:**
```
$ sudo aptitude install python-jsonpath-rw python-json-pointer
$ git clone https://github.com/nanobot248/ssltools.git
```
## COMMANDS

### Get Certificate Chain Information
Use `get-ssl-certificate-chain.py` to get the certificate chain from a server (optionally using an SNI name):
```
usage: get-ssl-certificate-chain.py [-h] --host HOST [-p PORT] [-s SNI_NAME]
                                    [--json-pointer JSON_POINTER]
                                    [--json-path JSON_PATH [JSON_PATH ...]]
                                    [-u] [-r]

Get and process SSL certificate chains.

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Hostname/IP to connect to.
  -p PORT, --port PORT  Port to connect to (defaults to 443)
  -s SNI_NAME, --sni-name SNI_NAME
                        SNI name to send to the server. Use this if the host
                        supports multiple SSL certificates.
  --json-pointer JSON_POINTER
                        JSON pointer query string (RFC6901) to get a specific
                        attribute from the certificate data.
  --json-path JSON_PATH [JSON_PATH ...]
                        JSON path (http://goessner.net/articles/JsonPath/)
                        filter string to query a subset of the certificate
                        data. Multiple queries can be specified that are
                        executed in order on the result of the previous query.
  -u, --unwrap          Unwrap transforms different data types into a simpler
                        format. If a result is a simple string, or a datetime
                        the quotes are removed. If the result is a X509 name,
                        its parts are joined to a string in the way used by
                        openssl (C=..., O=..., OU=..., CN=...)
  -r, --raw             Just get the certificate chain in PEM format and print
                        it to standard output.
```

### Verify Certificates
Use `verify-certificates.py` to verify PEM-formatted certificates provided on standard input. The certificates are parsed and verified against the system-wide CA certificates (/etc/ssl/certs/ca-certificates.crt).

```
usage: verify-certificates.py [-h] [--summary] [--only {valid,invalid}]
                              [--json-pointer JSON_POINTER]
                              [--json-path JSON_PATH [JSON_PATH ...]] [-u]

Verify the certificates provided in PEM format on STDIN.

optional arguments:
  -h, --help            show this help message and exit
  --summary, -s         Only return a summary value 'Valid' or 'Invalid'.
  --only {valid,invalid}, -o {valid,invalid}
                        Return an array of either only valid or invalid
                        certificates.
  --json-pointer JSON_POINTER
                        JSON pointer query string (RFC6901) to get a specific
                        attribute from the result. This is not applied in
                        --summary mode.
  --json-path JSON_PATH [JSON_PATH ...]
                        JSON path (http://goessner.net/articles/JsonPath/)
                        filter string to query a subset of the result data.
                        Multiple queries can be specified that are executed in
                        order on the result of the previous query. This
                        parameter is not used if --summary mode is used.
  -u, --unwrap          Unwrap transforms different data types into a simpler
                        format. If a result is a simple string, or a datetime
                        the quotes are removed. If the result is an X509 name,
                        its parts are joined to a string in the way used by
                        openssl (C=..., O=..., OU=..., CN=...). Unwrap has no
                        effect on a --summary value.
```

## LICENSE
This software is provided under the MIT license. See LICENSE file for more information.
