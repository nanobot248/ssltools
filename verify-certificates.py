#!/usr/bin/env python

import sys
import OpenSSL.crypto as crypto
from ssltools.certificates import verify_certificate, find_certificates, load_certificate_store, certificate_to_dict
import json
from ssltools.json import to_json
import argparse
from jsonpointer import resolve_pointer
from jsonpath_rw import jsonpath, parse

if __name__ == "__main__":
    cli = argparse.ArgumentParser(description = "Verify the certificates provided in PEM format on STDIN.")
    cli.add_argument("--summary", "-s", dest = "summary", action = "store_true",
        help = "Only return a summary value 'Valid' or 'Invalid'.")
    cli.add_argument("--only", "-o", dest = "only", choices = ["valid", "invalid"],
        help = "Return an array of either only valid or invalid certificates.")
    cli.add_argument("--json-pointer", dest = "json_pointer", type = str, nargs = 1,
        help = "JSON pointer query string (RFC6901) to get a specific attribute from the result. " +
        "This is not applied in --summary mode.")
    cli.add_argument("--json-path", dest = "json_path", nargs = "+",
        help = "JSON path (http://goessner.net/articles/JsonPath/) filter string " +
        "to query a subset of the result data. Multiple queries can be specified that are executed in " +
        "order on the result of the previous query. This parameter is not used if " +
        "--summary mode is used.")
    cli.add_argument("-u", "--unwrap", dest = "unwrap", action = "store_true",
        help = "Unwrap transforms different data types into a simpler format. If a result is a simple string, " +
        "or a datetime the quotes are removed. If the result is an X509 name, its parts are joined to a string " +
        "in the way used by openssl (C=..., O=..., OU=..., CN=...). Unwrap has no effect on " +
        "a --summary value.")
    args = cli.parse_args()

    cert = sys.stdin.read()
    certs = find_certificates(cert)

    in_certs = []
    for cert in certs:
        in_certs.append(crypto.load_certificate(crypto.FILETYPE_PEM, cert))

    store = load_certificate_store()

    good_certs = []
    while len(in_certs) > 0:
        good = []
        for cert in in_certs:
            if verify_certificate(cert, store):
                good.append(cert)
        if len(good) < 1: break
        for cert in good:
            try: store.add_cert(cert)
            except: pass
            in_certs.remove(cert)
            good_certs.append(cert)

    if args.summary:
        only_valid = len(in_certs) < 1
        result = ["Invalid", "Valid"][only_valid]
        print result
        sys.exit(0)

    tmp_certs = []
    for cert in good_certs:
        cert = certificate_to_dict(cert)
        cert["verificationValid"] = True
        tmp_certs.append(cert)
    good_certs = tmp_certs

    tmp_certs = []
    for cert in in_certs:
        cert = certificate_to_dict(cert)
        cert["verificationValid"] = False
        tmp_certs.append(cert)
    in_certs = tmp_certs
    tmp_certs = None

    out_certs = None

    if args.only != None:
        if args.only == "valid":
            out_certs = good_certs
        else:
            out_certs = in_certs
    else:
        out_certs = []
        for cert in in_certs: out_certs.append(cert)
        for cert in good_certs: out_certs.append(cert)

    if args.json_path != None and len(args.json_path) > 0:
        for pathExpression in args.json_path:
            expr = parse(pathExpression)
            out_certs = [match.value for match in expr.find(out_certs)]
    if args.json_pointer != None and len(args.json_pointer) > 0:
        pointer = args.json_pointer[0]
        out_certs = resolve_pointer(out_certs, pointer)

    if args.unwrap and isinstance(out_certs, str):
        jsonData = out_certs
    elif args.unwrap and isinstance(jsonCerts, datetime):
        jsonData = out_certs.isoformat()
    elif args.unwrap and isinstance(out_certs, dict):
        jsonData = ""
        for key in out_certs:
            jsonData += key + "=" + out_certs[key] + ", "
        if len(jsonData) > 0: jsonData = jsonData[0:-2]
    else:
        jsonData = to_json(out_certs, pretty = True)

    print jsonData
