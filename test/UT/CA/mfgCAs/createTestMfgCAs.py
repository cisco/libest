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

Continuing will completely erase/destroy/nuke the existing 
TestMfgCAs\
"""
msg_destroy_alert = """\
Nuking from orbit!
#################################################################\
"""

msg_create_CA = """\
#################################################################
####(Re)creating an initial root TestMfg%d CA certificate
#################################################################\
"""
msg_done_line = """\
#################################################################\
"""
msg_server_combine = """\
#################################################################
####Creating combined trusted cert file for server\
"""
msg_mfg_chain_combine = """\
#################################################################
####Creating combined trusted cert file for client\
"""
testmfg_subj_line_additions = ['/serialNumber=SN:x, PID:x', '',
                               '/O=ToysRUsKnockOff',
                               '/OU=IOOT(Internet Of Other Things)',
                               '/uniqueMember=TheSecretCertClub']

detectWindowsFlag()
print(msg_start_warn)
try:
    input("Press Enter to continue...")
except:
    print("")
print(msg_destroy_alert)
for i in range(5):
    print('\"'+ "/CN=127.0.0.1" +
                          testmfg_subj_line_additions[i] + '\"')

trustedfile_write_state = "w"
for i in range(5):
    EST_OPENSSL_TESTMFGCADIR = "TestMfgCA%d" % (i)
    EST_OPENSSL_TESTMFGCACNF = "estExampleTestMfgCA.cnf"
    EST_OPENSSL_INT_TESTMFGCACNF = "estExampleIntTestMfgCA.cnf"
    EST_OPENSSL_TESTMFGCACERT = "%s/cacert.crt" % EST_OPENSSL_TESTMFGCADIR
    EST_OPENSSL_TESTMFGCAPRIVDIR = "%s/private" % EST_OPENSSL_TESTMFGCADIR
    EST_OPENSSL_TESTMFGCANEWCERTSDIR = "%s/newcerts" % EST_OPENSSL_TESTMFGCADIR
    EST_OPENSSL_TESTMFGCADATABASE = "%s/index.txt" % EST_OPENSSL_TESTMFGCADIR
    EST_OPENSSL_TESTMFGCASERIAL = "%s/serial" % EST_OPENSSL_TESTMFGCADIR
    EST_OPENSSL_TESTMFGCAPRIVKEY = "%s/cakey.pem" % EST_OPENSSL_TESTMFGCAPRIVDIR
    EST_OPENSSL_TESTMFGCAPRIVKEYPARAM = "%s/cakeyparam.pem" % EST_OPENSSL_TESTMFGCAPRIVDIR
    EST_OPENSSL_TESTMFGCASUBJ = "/CN=estExampleTestMfg%dCA" % (i)

    EST_OPENSSLCMD_TESTMFGCAECPARAMSFILE = "%s/prime256v1.pem" % EST_OPENSSL_TESTMFGCADIR
    EST_OPENSSLCMD_TESTMFGCANEWKEY_PARAM = "-newkey ec:%s" % EST_OPENSSLCMD_TESTMFGCAECPARAMSFILE

    EST_TESTMFG_SUBJ = "/CN=127.0.0.1"
    EST_TESTMFG_CERTREQ = "%s/esttestmfg%d.req" % (EST_OPENSSL_TESTMFGCADIR, i)
    EST_TESTMFG_CERT = "esttestmfg%d.crt" % (i)
    EST_TESTMFG_PRIVKEY = "esttestmfg%d.pem" % (i)
    EST_TESTMFG_CCAUTHZDB = "ccAuthz.db"
    os.environ["MFGNUM"] = "%d" % (i)

    shutil.rmtree(EST_OPENSSL_TESTMFGCADIR, ignore_errors=True)
    print(msg_create_CA)
    createCA(EST_OPENSSL_TESTMFGCASUBJ,
             EST_OPENSSL_TESTMFGCADIR,
             EST_OPENSSL_TESTMFGCACERT,
             EST_OPENSSL_TESTMFGCAPRIVDIR,
             EST_OPENSSL_TESTMFGCASERIAL,
             EST_OPENSSL_TESTMFGCADATABASE,
             EST_OPENSSL_TESTMFGCANEWCERTSDIR,
             EST_OPENSSL_TESTMFGCAPRIVKEY,
             EST_OPENSSLCMD_TESTMFGCANEWKEY_PARAM,
             EST_OPENSSLCMD_TESTMFGCAECPARAMSFILE)

    createIntermediateCAs(EST_OPENSSL_TESTMFGCADIR,
                          EST_OPENSSL_TESTMFGCACERT,
                          EST_OPENSSL_TESTMFGCAPRIVKEY,
                          EST_OPENSSL_TESTMFGCAPRIVKEYPARAM,
                          EST_OPENSSLCMD_TESTMFGCANEWKEY_PARAM,
                          '\"'+EST_TESTMFG_SUBJ +
                          testmfg_subj_line_additions[i] + '\"',
                          EST_OPENSSL_TESTMFGCACNF,
                          EST_OPENSSL_INT_TESTMFGCACNF,
                          EST_OPENSSL_TESTMFGCASUBJ,
                          EST_TESTMFG_CERT,
                          EST_TESTMFG_PRIVKEY,
                          "testmfg%d_chain.crt" % (i),
                          1,
                          1)

    print(msg_server_combine)
    with open("../trustedcerts.crt", trustedfile_write_state) as fileout:
        with open("TestMfgCA%d/cacert.crt" % (i)) as filein:
            fileout.write(filein.read())
    trustedfile_write_state = "a"
    print(msg_done_line)

    print(msg_mfg_chain_combine)
    combinefiles("../estCA/cacert.crt", "testmfg%d_chain.crt" % (i),
                 "trustedcertswithmfg%dchain.crt" % (i))
    print(msg_done_line)

# Add Non-Mfg trusted certificates to Mfg trusted certificate file
print(msg_server_combine)
with open("../trustedcerts.crt", trustedfile_write_state) as fileout:
    with open("../estCA/cacert.crt") as filein:
        fileout.write(filein.read())
with open("../trustedcerts.crt", trustedfile_write_state) as fileout:
    with open("../extCA/cacert.crt") as filein:
        fileout.write(filein.read())
print(msg_done_line)

print("Resetting the est server password file")
with open("../estCA/estpwdfile", "w") as file:
    file.write("estuser:estrealm:36807fa200741bb0e8fb04fcf08e2de6")
