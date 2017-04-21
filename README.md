# ssltools

## Table of Contents
* [OVERVIEW](#overview)
* [INSTALLATION](#installation)
* [COMMANDS](#commands)
* [LICENSE](#license)

## OVERVIEW
This repository provides some tools for getting, verifying and processing SSL certificates. Certificates can be converted into a JSON representation and filtered with [jsonpath](http://goessner.net/articles/JsonPath/) and json pointer ([RFC6901](https://tools.ietf.org/html/rfc6901)).

I wrote these scripts mostly for easier certificate expiry and CN monitoring with Zabbix. Therefore, it also provides "unwrapping" of certain data types (e.g. removing double quotes from output if the output is a JSON string)

## INSTALLATION
The tools require python "jsonpath" and "jsonpointer" packages (`python-jsonpath-rw` and `python-jsonpointer` in Debian/Ubuntu) and a working `openssl` command. The `openssl`command must be available in the PATH environment variable.

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

#### Unwrapping
Unwrapping of results works only for a single result that was filtered out via JSON pointer, e.g. by using `/0/subject`. Using JSONPath or no filtering at all, the result will always be an array and will not be unwrapped.

Unwrapping currently does the following:
* x509Name objects: The components of the name are joined in the format `comp1=value2, comp2=value2, ...`. This format is not invertible in all cases. It would be possible to create certificates with values like `O= , CN=bla, CN=test` (using `{"O": " ,CN=bla", "CN": "test"}` (i've successfully tried this with openssl). Although this is not a very realistic case, it may be relevant for security.
* Strings: Strings will simply be printed without quotes.
* datetime objects: The certificate ASN.1 generalized datetime is converted to python datetime.datetime objects. These datetime objects are then converted to ISO strings (`datetime.isoformat()`). Therefore, in the JSON representation, datetime objects are strings and using `-u` will simply remove the double quotes.

#### Examples:
Get all subjects for SNI name www.google.at from host www.google.com:
```
$ ./get-ssl-certificate-chain.py --host www.google.com -p 443 -s www.google.at --json-path "$.[*].['subject']"
[
  {
    "C": "US", 
    "CN": "*.google.at", 
    "L": "Mountain View", 
    "O": "Google Inc", 
    "ST": "California"
  }, 
  {
    "C": "US", 
    "CN": "Google Internet Authority G2", 
    "O": "Google Inc"
  }, 
  {
    "C": "US", 
    "CN": "GeoTrust Global CA", 
    "O": "GeoTrust Inc."
  }
]
```
Get only the subject of the first certificate in the chain (should be the peer certificate) and unwrap it (which means the x509Name components are jointed into a single string and the string is not wrapped in double quotes):
```
$ ./get-ssl-certificate-chain.py --host www.google.com -p 443 -s www.google.at --json-pointer "/0/subject" -u
CN=*.google.at, C=US, L=Mountain View, O=Google Inc, ST=California
```

The same without unwrapping:
```
$ ./get-ssl-certificate-chain.py --host www.google.com -p 443 -s www.google.at --json-pointer "/0/subject" 
{
  "C": "US", 
  "CN": "*.google.at", 
  "L": "Mountain View", 
  "O": "Google Inc", 
  "ST": "California"
}
```
### Verify Certificates
Use `verify-certificates.py` to verify PEM-formatted certificates provided on standard input. The certificates are parsed and verified against the system-wide CA certificates (/etc/ssl/certs/ca-certificates.crt).
Like `get-ssl.certificate-chain.py`, the command supports filtering via JSONPath and JSON pointer, as well as unwrapping. In standard mode, it will add a `verificationValid` property to each certificate that tells whether the certificate could be verified against the local CAs and the the other certificates in the chain.
With `--only`, only `valid` or `invalid` certificates will be printed.

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
#### Examples
Get all certificates of the server using `get-ssl-certificate-chain.py`, print them out as raw PEM (`-r` parameter) and verify them:
```
$ ./get-ssl-certificate-chain.py --host www.google.com -p 443 -s www.google.at --json-pointer "/0/subject" -r | ./verify-certificates.py 
[
  {
    "expired": false, 
    "extensions": [... removed for readability ...], 
    "issuer": {
      "C": "US", 
      "CN": "GeoTrust Global CA", 
      "O": "GeoTrust Inc."
    }, 
    "notAfter": "2017-12-31T23:59:59", 
    "notBefore": "2015-04-01T00:00:00", 
    "serial": 146066, 
    "signatureAlgorithm": "sha256WithRSAEncryption", 
    "subject": {
      "C": "US", 
      "CN": "Google Internet Authority G2", 
      "O": "Google Inc"
    }, 
    "validFor": 254, 
    "validSince": 751, 
    "verificationValid": true
  }, 
  {
    "expired": false, 
    "extensions": [... removed for readability ...], 
    "issuer": {
      "C": "US", 
      "O": "Equifax", 
      "OU": "Equifax Secure Certificate Authority"
    }, 
    "notAfter": "2018-08-21T04:00:00", 
    "notBefore": "2002-05-21T04:00:00", 
    "serial": 1227750, 
    "signatureAlgorithm": "sha1WithRSAEncryption", 
    "subject": {
      "C": "US", 
      "CN": "GeoTrust Global CA", 
      "O": "GeoTrust Inc."
    }, 
    "validFor": 486, 
    "validSince": 5449, 
    "verificationValid": true
  }, 
  {
    "expired": false, 
    "extensions": [... removed for readability ...], 
    "issuer": {
      "C": "US", 
      "CN": "Google Internet Authority G2", 
      "O": "Google Inc"
    }, 
    "notAfter": "2017-07-05T13:28:00", 
    "notBefore": "2017-04-12T13:28:00", 
    "serial": 8963580107717764213, 
    "signatureAlgorithm": "sha256WithRSAEncryption", 
    "subject": {
      "C": "US", 
      "CN": "*.google.at", 
      "L": "Mountain View", 
      "O": "Google Inc", 
      "ST": "California"
    }, 
    "validFor": 74, 
    "validSince": 9, 
    "verificationValid": true
  }
]
```

## LICENSE
This software is provided under the MIT license. See LICENSE file for more information.
