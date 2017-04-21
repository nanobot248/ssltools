import subprocess as proc

_opensslPath = None
def openssl_path():
    """Get full path of the openssl command line tool.
    Uses "which" to get the path of the "openssl" command. This can be used to
    execute openssl directly without setting shell = True in Popen.
    """
    global _opensslPath
    if _opensslPath == None:
        _opensslPath = proc.check_output("which openssl", shell = True).strip()
    return _opensslPath

def call_openssl(args, input = None):
    """Call the openssl command line tool.
    "args" should be an array of command line parameters. "input" is an
    optional parameter that will be used as standard input to openssl. This
    can be used e.g. to quit openssl (input = "Q\n") after it has been startet.
    """
    opensslCommandLine = [openssl_path()] + args
    openssl = proc.Popen(opensslCommandLine, stdin=proc.PIPE, stdout=proc.PIPE, stderr=proc.PIPE)
    (out, err) = openssl.communicate(input)
    return {
        "out": out,
        "err": err,
        "code": openssl.returncode
    }
