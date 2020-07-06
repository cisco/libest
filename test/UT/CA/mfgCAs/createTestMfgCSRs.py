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
TestMfg CSRs\
"""
msg_destroy_alert = """\
Nuking test CSRs!
#################################################################\
"""
msg_done_line = """\
#################################################################\
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
for i in range(5):
    EST_OPENSSL_TESTMFGCADIR = "TestMfgCA%d" % (i)
    EST_OPENSSL_TESTMFGCACNF = "estExampleTestMfgCA.cnf"

    EST_TESTMFG_CERTANDKEY = "%s/private/certandkey1-esttestmfg%d.pem" % (
        EST_OPENSSL_TESTMFGCADIR, i)
    EST_TESTMFG_CCAUTHZDB = "ccAuthz.db"
    os.environ["MFGNUM"] = "%d" % (i)
    createCSR("TestMfgCA%d/test.csr" % (i), EST_TESTMFG_CERTANDKEY, "/CN=127.0.0.1" +
              testmfg_subj_line_additions[i], EST_OPENSSL_TESTMFGCACNF)

    print(msg_done_line)
