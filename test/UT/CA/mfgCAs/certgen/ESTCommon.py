#! python

import os
import sys
from subprocess import call
est_logging_file = "estserver.scripts.log"
openssl_cmd = "openssl"
prev_code = 0
windows = False
EST_OPENSSL_CACNF = "estExampleCA.cnf"
logandexit_msg = \
    """\
###########..EXIT..##########
SCRIPT $EST_SCRIPTNAME EXIT: %s (%d)
###########^^EXIT^^##########
 \
"""
headers_msg = \
    """\
Headers:
%s
/Headers\
"""

content_msg = \
    """\
Content:
%s
/Content\
"""


def logandexit(msg, code):
    with open(est_logging_file, "w") as file:
        file.write(logandexit_msg % (msg, code))
        sys.exit(code)


def iferrorlogandexit(msg, code):
    if prev_code:
        logandexit(msg, code)


def dumpheadersandcontent(header_file, content_file):
    with open(est_logging_file, "w") as file:
        if header_file:
            with open(header_file, "r") as headers:
                file.write(headers_msg % (headers.read()))
        if content_file:
            with open(content_file, "r") as content:
                file.write(content_msg % (content.read()))


def iferrorheaderslogandexit(search_hdr, hdr_file, log_msg, content_file):
    if not search_hdr in open(hdr_file).read:
        dumpheadersandcontent(hdr_file, content_file)
        logandexit("Header ERROR: %s" % log_msg, 1)


def cert2pkcs72stdout(crt_file):
    print("Content-Type: application/pkcs7-mime")
    print("")
    system("%s crl2pkcs7 -certfile %s -nocrl" %
           (openssl_cmd, crt_file))


def combinefiles(file1, file2, outfile):
    with open(outfile, "w") as fileout:
        with open(file1) as file:
            fileout.write(file.read())
    with open(outfile, "a") as fileout:
        with open(file2) as file:
            fileout.write(file.read())


def touch(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)


def system(cmd):
    if windows:
        cmd = cmd.replace('/', '\\')
    prev_code = call(cmd, shell=True)
    return prev_code


def detectWindowsFlag():
    global windows
    if (len(sys.argv) > 1):
        windows = (sys.argv[1] == "-w")
