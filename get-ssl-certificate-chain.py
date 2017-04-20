#!/usr/bin/env python

import subprocess as proc
import sys
import os
import re
from pprint import pprint
import OpenSSL.crypto as crypto
import json
import base64
import datetime
from jsonpointer import resolve_pointer
from jsonpath_rw import jsonpath, parse
import argparse

CERT_REGEX = re.compile('-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----')

def readCerts(text):
    m = re.search(CERT_REGEX, text)
    certs = []
    while m != None:
        certs.append(m.group(0).strip())
        text = text[m.end():-1]
        m = re.search(CERT_REGEX, text)
    return certs

def certNameToDict(name):
    result = {}
    for (key,value) in name.get_components():
        result[key] = value
    return result

def parseGeneralizedDatetime(ts):
    result = None
    if ts[-1] == "Z":
        result = datetime.datetime.strptime(ts, "%Y%m%d%H%M%SZ")
    elif ts[-5] == "+" or ts[-5] == "-":
        result = datetime.datetime.strptime(ts, "%Y%m%d%H%M%S%z")
    else:
        result = datetime.datetime.strptime(ts, "%Y%m%d%H%M%S")
    return result

def certToDict(cert):
    now = datetime.datetime.now()
    result = {}
    result["issuer"] = certNameToDict(cert.get_issuer())
    result["subject"] = certNameToDict(cert.get_subject())
    result["notBefore"] = parseGeneralizedDatetime(cert.get_notBefore())
    result["notAfter"] = parseGeneralizedDatetime(cert.get_notAfter())
    result["validSince"] = int((now - result["notBefore"]).total_seconds() / (24 * 3600))
    result["validFor"] = int((result["notAfter"] - now).total_seconds() / (24 * 3600))
    result["serial"] = cert.get_serial_number()
    result["signatureAlgorithm"] = cert.get_signature_algorithm()
    result["expired"] = cert.has_expired()
    result["extensions"] = []
    for i in xrange(0, cert.get_extension_count()):
        value = {}
        ext = cert.get_extension(i)
        value["asString"] = ext.__str__()
        value["criticalField"] = ext.get_critical()
        value["shortName"] = ext.get_short_name()
        data = ext.get_data();
        value["data"] = base64.b64encode(data)
        result["extensions"].append(value)
    return result

def serializer(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj.__str__()

if __name__ == "__main__":
    cli = argparse.ArgumentParser(description = "Get and process SSL certificate chains.")
    cli.add_argument("--host", dest = "host", nargs = 1, type = str, required = True)
    cli.add_argument("-p", "--port", dest = "port", type = int, nargs = 1, default = 443)
    cli.add_argument("-s", "--sni-name", dest = "sni_name", type = str, nargs = 1)
    cli.add_argument("--json-pointer", dest = "json_pointer", type = str, nargs = 1)
    cli.add_argument("--json-path", dest = "json_path", nargs = "+")
    cli.add_argument("-u", "--unwrap", dest = "unwrap", action = "store_true")
    args = cli.parse_args()

    opensslPath = proc.check_output("which openssl", shell = True).strip()

    opensslCommandLine = [opensslPath, "s_client", "-connect", "%s:%i" % (args.host[0], args.port[0]), "-prexit", "-showcerts"]
    if args.sni_name != None and len(args.sni_name) > 0:
        opensslCommandLine.append("-servername")
        opensslCommandLine.append(args.sni_name[0])
    openssl = proc.Popen(opensslCommandLine, stdin=proc.PIPE, stdout=proc.PIPE, stderr=proc.PIPE)
    (out, err) = openssl.communicate("Q\n")

    if openssl.returncode != 0:
        print >> sys.stderr, "Error: Failure executing openssl command.\n"
        print >> sys.stderr, err
        sys.exit(1)

    if out != None and out != "":
        plainCerts = readCerts(out)
        certs = []
        jsonCerts = []
        for cert in plainCerts:
            certs.append(crypto.load_certificate(crypto.FILETYPE_PEM, cert))
        for cert in certs:
            jsonCerts.append(certToDict(cert))
        if args.json_path != None and len(args.json_path) > 0:
            for pathExpression in args.json_path:
                expr = parse(pathExpression)
                jsonCerts = [match.value for match in expr.find(jsonCerts)]
        if args.json_pointer != None and len(args.json_pointer) > 0:
            pointer = args.json_pointer[0]
            jsonCerts = resolve_pointer(jsonCerts, pointer)
        if args.unwrap and isinstance(jsonCerts, str):
            jsonData = jsonCerts
        elif args.unwrap and isinstance(jsonCerts, datetime.datetime):
            jsonData = jsonCerts.isoformat()
        else:
            jsonData = json.dumps(jsonCerts, indent = 2, sort_keys = True, default = serializer)
        print jsonData
    else:
        print >> sys.stderr, "no output!"
