#!/usr/bin/env python

import sys
import os
import re
import OpenSSL.crypto as crypto
import json
from jsonpointer import resolve_pointer
from jsonpath_rw import jsonpath, parse
import argparse
from datetime import datetime

import ssltools.certificates as certificates
from ssltools.openssl import call_openssl
from ssltools.json import to_json

if __name__ == "__main__":
    cli = argparse.ArgumentParser(description = "Get and process SSL certificate chains.")
    cli.add_argument("--host", dest = "host", nargs = 1, type = str, required = True,
        help = "Hostname/IP to connect to.")
    cli.add_argument("-p", "--port", dest = "port", type = int, nargs = 1, default = 443,
        help = "Port to connect to (defaults to 443)")
    cli.add_argument("-s", "--sni-name", dest = "sni_name", type = str, nargs = 1,
        help = "SNI name to send to the server. Use this if the host supports multiple SSL certificates.")
    cli.add_argument("--json-pointer", dest = "json_pointer", type = str, nargs = 1,
        help = "JSON pointer query string (RFC6901) to get a specific attribute from the certificate data.")
    cli.add_argument("--json-path", dest = "json_path", nargs = "+",
        help = "JSON path (http://goessner.net/articles/JsonPath/) filter string " +
        "to query a subset of the certificate data. Multiple queries can be specified that are executed in " +
        "order on the result of the previous query.")
    cli.add_argument("-u", "--unwrap", dest = "unwrap", action = "store_true",
        help = "Unwrap transforms different data types into a simpler format. If a result is a simple string, " +
        "or a datetime the quotes are removed. If the result is a X509 name, its parts are joined to a string " +
        "in the way used by openssl (C=..., O=..., OU=..., CN=...)")
    cli.add_argument("-r", "--raw", dest = "raw", action = "store_true",
        help = "Just get the certificate chain in PEM format and print it to standard output.")
    args = cli.parse_args()

    opensslCommandLine = ["s_client", "-connect", "%s:%i" % (args.host[0], args.port[0]), "-showcerts"]
    if args.sni_name != None and len(args.sni_name) > 0:
        opensslCommandLine.append("-servername")
        opensslCommandLine.append(args.sni_name[0])
    openssl = call_openssl(opensslCommandLine, "Q\n")
    if openssl['code'] != 0:
        print >> sys.stderr, "Error: Failure executing openssl command.\n"
        print >> sys.stderr, openssl['err']
        sys.exit(1)

    if openssl['out'] != None and openssl['out'] != "":
        plainCerts = certificates.find_certificates(openssl['out'])
        if args.raw:
            for cert in plainCerts:
                print cert
            sys.exit(0)
        certs = []
        jsonCerts = []
        for cert in plainCerts:
            certs.append(crypto.load_certificate(crypto.FILETYPE_PEM, cert))
        for cert in certs:
            jsonCerts.append(certificates.certificate_to_dict(cert))
        if args.json_path != None and len(args.json_path) > 0:
            for pathExpression in args.json_path:
                expr = parse(pathExpression)
                jsonCerts = [match.value for match in expr.find(jsonCerts)]
        if args.json_pointer != None and len(args.json_pointer) > 0:
            pointer = args.json_pointer[0]
            jsonCerts = resolve_pointer(jsonCerts, pointer)

        if args.unwrap and isinstance(jsonCerts, str):
            jsonData = jsonCerts
        elif args.unwrap and isinstance(jsonCerts, datetime):
            jsonData = jsonCerts.isoformat()
        elif args.unwrap and isinstance(jsonCerts, dict):
            jsonData = ""
            for key in jsonCerts:
                jsonData += key + "=" + jsonCerts[key] + ", "
            if len(jsonData) > 0: jsonData = jsonData[0:-2]
        else:
            jsonData = to_json(jsonCerts, pretty = True)

        print jsonData
    else:
        print >> sys.stderr, "no output!"
