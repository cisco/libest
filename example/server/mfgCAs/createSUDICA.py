#!python
import shutil
from certgen import *
msg_start_warn = """\
#################################################################
SECURITY CONSIDERATIONS - NOTE WELL
The sample scripts used to handle EST operations are NOT
intended to provide a secure implementation. They have not
been evaluated for security, they have not had a Threat Model
reviewed, they are not particularly good about cleaning up after
themselves and they assume the data exchanged is well formed
if the cryptographic checks pass.

In short: They are not to be trusted. They provide a functional
implementation only.

Continuing will completely erase/destroy/nuke the existing sudiCA\
"""
msg_destroy_alert = """\
Nuking from orbit!
#################################################################\
"""

msg_create_CA = """\
#################################################################
####(Re)creating an initial root SUDI CA certificate
#################################################################\
"""
msg_done_line = """\
#################################################################\
"""
msg_server_combine = """\
#################################################################
####Creating combined trusted cert file for server\
"""
msg_sudi_combine = """\
#################################################################
####Creating combined trusted cert file for client\
"""
msg_huge_combine = """\
#################################################################
####Creating combined trusted cert files for huge cert test\
"""


EST_OPENSSL_SUDICADIR = "sudiCA"
EST_OPENSSL_SUDICACNF = "estExampleSUDICA.cnf"
EST_OPENSSL_INT_SUDICACNF = "estExampleIntSUDICA.cnf"
EST_OPENSSL_SUDICACERT = "%s/cacert.crt" % EST_OPENSSL_SUDICADIR
EST_OPENSSL_SUDICAPRIVDIR = "%s/private" % EST_OPENSSL_SUDICADIR
EST_OPENSSL_SUDICANEWCERTSDIR = "%s/newcerts" % EST_OPENSSL_SUDICADIR
EST_OPENSSL_SUDICADATABASE = "%s/index.txt" % EST_OPENSSL_SUDICADIR
EST_OPENSSL_SUDICASERIAL = "%s/serial" % EST_OPENSSL_SUDICADIR
EST_OPENSSL_SUDICAPRIVKEY = "%s/cakey.pem" % EST_OPENSSL_SUDICAPRIVDIR
EST_OPENSSL_SUDICAPRIVKEYPARAM = "%s/cakeyparam.pem" % EST_OPENSSL_SUDICAPRIVDIR
EST_OPENSSL_SUDICASUBJ = "/CN=estExampleSUDICA"

EST_OPENSSLCMD_SUDICAECPARAMSFILE = "%s/prime256v1.pem" % EST_OPENSSL_SUDICADIR
EST_OPENSSLCMD_SUDICANEWKEY_PARAM = "-newkey ec:%s" % EST_OPENSSLCMD_SUDICAECPARAMSFILE

EST_SUDI_SUBJ = "/CN=127.0.0.1"
EST_SUDI_CERTREQ = "%s/estsudi.req" % EST_OPENSSL_SUDICADIR
EST_SUDI_CERT = "%s/estsudi.crt" % EST_OPENSSL_SUDICADIR
EST_SUDI_PRIVKEY = "estsudi.pem"
EST_SUDI_CERTANDKEY = "%s/estsudicertandkey.pem" % EST_OPENSSL_SUDICAPRIVDIR
EST_SUDI_CCAUTHZDB = "ccAuthz.db"

detectWindowsFlag()
print(msg_start_warn)
try:
    input("Press Enter to continue...")
except:
    print("")
print(msg_destroy_alert)
shutil.rmtree(EST_OPENSSL_SUDICADIR, ignore_errors=True)
print(msg_create_CA)
createCA(EST_OPENSSL_SUDICASUBJ,
         EST_OPENSSL_SUDICADIR,
         EST_OPENSSL_SUDICACERT,
         EST_OPENSSL_SUDICAPRIVDIR,
         EST_OPENSSL_SUDICASERIAL,
         EST_OPENSSL_SUDICADATABASE,
         EST_OPENSSL_SUDICANEWCERTSDIR,
         EST_OPENSSL_SUDICAPRIVKEY,
         EST_OPENSSLCMD_SUDICANEWKEY_PARAM,
         EST_OPENSSLCMD_SUDICAECPARAMSFILE)

createIntermediateCAs(EST_OPENSSL_SUDICADIR,
                      EST_OPENSSL_SUDICACERT,
                      EST_OPENSSL_SUDICAPRIVKEY,
                      EST_OPENSSL_SUDICAPRIVKEYPARAM,
                      EST_OPENSSLCMD_SUDICANEWKEY_PARAM,
                      EST_SUDI_SUBJ,
                      EST_OPENSSL_SUDICACNF,
                      EST_OPENSSL_INT_SUDICACNF,
                      EST_OPENSSL_SUDICASUBJ,
                      EST_SUDI_PRIVKEY,
                      EST_SUDI_CERT,
                      "sudi_chain.crt",
                      2,
                      1)

print(msg_server_combine)
with open("../trustedcerts.crt", "a") as fileout:
    with open("sudiCA/cacert.crt") as filein:
        fileout.write(filein.read())

print(msg_done_line)

print(msg_sudi_combine)
combinefiles("../estCA/cacert.crt", "sudi_chain.crt",
             "trustedcertswithsudichain.crt")
print(msg_done_line)

print("Resetting the est server password file")
with open("../estCA/estpwdfile", "w") as file:
    file.write("estuser:estrealm:36807fa200741bb0e8fb04fcf08e2de6")
