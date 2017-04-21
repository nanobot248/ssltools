import re
from datetime import datetime
import base64
import os
import os.path
import OpenSSL.crypto as crypto

# Regular expression to find PEM formatted certificates in text.
CERT_REGEX = re.compile('-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----')

def find_certificates(text):
    """Find certificates inside text.
    The method searches for PEM-formatted certificate blocks inside plain text
    and returns a list of such text blocks.
    """
    text = "   \n%s\n   \n" % text
    m = re.search(CERT_REGEX, text)
    certs = []
    while m != None:
        certs.append(m.group(0).strip())
        text = text[m.end(0):-1]
        m = re.search(CERT_REGEX, text)
    return certs

def name_to_dict(name):
    """Convert OpenSSL x509Name to dict object.
    Creates a dict with all the components of the x509Name object and
    returns it.
    """
    result = {}
    for (key,value) in name.get_components():
        result[key] = value
    return result

def parse_generalized_datetime(ts):
    """Parse an ASN.1 generalized datetime string.
    Currently, only fractionless strings are supported. The result is returned
    as a datetime object.
    """
    result = None
    if ts[-1] == "Z":
        result = datetime.strptime(ts, "%Y%m%d%H%M%SZ")
    elif ts[-5] == "+" or ts[-5] == "-":
        result = datetime.strptime(ts, "%Y%m%d%H%M%S%z")
    else:
        result = datetime.strptime(ts, "%Y%m%d%H%M%S")
    return result

def certificate_to_dict(cert):
    """Converts an OpenSSL x509 object to a dict.
    Creates a dict and puts the information provided by the x509 certificate
    object into it. Currently, the following information is provided:
        issuer: dict of x509Name issuer
        subject: dict of x509Name subject
        notBefore: datetime of the "don't use before" value.
        notAfter: datetime of the "don't use after" value.
        validSince: Number of days since the certificate has become valid (int).
        validFor: Number of days until the certificate will expire (as int).
        serial: Serial number.
        signatureAlgorithm: Signature algorithm.
        expired: Boolean telling whether the certificate has expired or not.
        extensions: A list of extensions provided by the x509 object. Each
            extension has the following key:
                asString: String representation of the extension data.
                criticalField: Critical field.
                shortName: Short name of the extension.
                data: The binary (base64) value of the extension's data.
    """
    now = datetime.now()
    result = {}
    result["issuer"] = name_to_dict(cert.get_issuer())
    result["subject"] = name_to_dict(cert.get_subject())
    result["notBefore"] = parse_generalized_datetime(cert.get_notBefore())
    result["notAfter"] = parse_generalized_datetime(cert.get_notAfter())
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

def load_certificate_store(path = "/etc/ssl/certs/ca-certificates.crt"):
    """Load certificates into a certificate store.
    Create a certificate store and load the certificates from the given path
    into it. The default path is the standard path of CA certificates in
    Linux (at least Debian and Ubuntu).
    """
    store = crypto.X509Store()
    with open(path, "r") as certfile:
        certs = certfile.read()
        certs = find_certificates(certs)
        for cert in certs:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            store.add_cert(cert)
    return store

def verify_certificate(cert, store = None):
    """Verify a certificate against a certificate store.
    If no store is provided, the default store is created. The certificate (
    provided as an x509 object) is verified against this store of trusted
    certificates.
    """
    if store == None:
        store = load_certificate_store()
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
        return True
    except Exception as ex:
        return False
