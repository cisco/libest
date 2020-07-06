#! python
from subprocess import call
import os
from ESTCommon import *

msg_CA = \
    """
#################################################################
####(Re)creating the directory structure and initial files" 
####for the CA: %s
#################################################################
"""
msg_int_cert = \
    """
#################################################################
####(Re)creating Level %d Intermediate certificate (Chain %d)
#################################################################
"""
msg_endpnt_crt = \
    """
#################################################################
####(Re)creating an initial peer certificate for an endpoint to 
#### use
#################################################################
"""


def createCA(CREATECA_CASUBJ,
             CREATECA_CADIR,
             CREATECA_CACERT,
             CREATECA_CAPRIVDIR,
             CREATECA_CASERIAL,
             CREATECA_CADATABASE,
             CREATECA_CANEWCERTSDIR,
             CREATECA_CAPRIVKEY,
             CREATECA_NEWKEY_PARAM,
             CREATECA_ECPARAMSFILE,
             ):
    print(msg_CA % (CREATECA_CASUBJ))
    os.makedirs(CREATECA_CADIR)
    os.makedirs(CREATECA_CAPRIVDIR)
    os.makedirs(CREATECA_CANEWCERTSDIR)
    with open(CREATECA_CASERIAL, "w") as serial_file:
        serial_file.write("01")
    touch(CREATECA_CADATABASE)
    system("%s ecparam -name prime256v1 -out %s" %
           (openssl_cmd, CREATECA_ECPARAMSFILE))
    iferrorlogandexit("Unable to build ECPARAMS file", 1)
    system("%s req -new -x509 -sha256 -extensions v3_ca %s -keyout %s -out %s -days 7305 -nodes -subj \"%s\" -config %s" %
           (openssl_cmd, CREATECA_NEWKEY_PARAM, CREATECA_CAPRIVKEY, CREATECA_CACERT, CREATECA_CASUBJ, EST_OPENSSL_CACNF))
    iferrorlogandexit("Unable to create \"%s\" CA cert" % (CREATECA_CASUBJ), 1)
    system("%s x509 -sha256 -in %s" % (openssl_cmd, CREATECA_CACERT))


def createIntermediateCAs(TMP_CADIR,
                          TMP_CACERT,
                          TMP_CAPRIVKEY,
                          TMP_CAPRIVKEYPARAM,
                          TMP_NEWKEY_CMD,
                          TMP_FINAL_SUBJ,
                          TMP_FINAL_CACNF,
                          TMP_INT_CACNF,
                          TMP_INT_SUBJ,
                          TMP_FINAL_CERT,
                          TMP_FINAL_PRIVKEY,
                          CHAIN_FILE,
                          NUM_INTER,
                          CHAIN_NUM,
                          EXT_FILE="./ext.cnf"):
    TMP_CERTANDKEY = "%s/private/certandkey%s-%s" % (
        TMP_CADIR, CHAIN_NUM, TMP_FINAL_PRIVKEY)
    TMP_FINAL_CERT = "%s/%s" % (TMP_CADIR, TMP_FINAL_CERT)
    TMP_FINAL_PRIVKEY = "%s/private/%s" % (TMP_CADIR, TMP_FINAL_PRIVKEY)
    TMP_CERTREQ = "%s/est.req" % (TMP_CADIR)
    with open(CHAIN_FILE, "w") as fileout:
        with open(TMP_CACERT) as filein:
            fileout.write(filein.read())
    if(NUM_INTER >= 0):
        for i in range(NUM_INTER):
            TMP_PRIVKEY = "%s/private/cakey%d-%d.pem" % (
                TMP_CADIR, CHAIN_NUM, i)
            TMP_CERT = "%s/cacert%d-%d.crt" % (TMP_CADIR, CHAIN_NUM, i)
            TMP_SUBJ = "%s%d-%d" % (TMP_INT_SUBJ, CHAIN_NUM, i)
            if not os.path.isfile(TMP_PRIVKEY):
                print(msg_int_cert % (i, CHAIN_NUM))
                system("%s req -new -sha256 -nodes -out %s %s -keyout %s -subj \"%s\" -config %s" %
                       (openssl_cmd, TMP_CERTREQ, TMP_NEWKEY_CMD, TMP_PRIVKEY, TMP_SUBJ, TMP_INT_CACNF))
                iferrorlogandexit(
                    "Unable to create est SUDI Int Lvl %d CSR" % (i), 1)
                system("%s ca -md sha256 -out %s -batch -config %s -infiles %s" %
                       (openssl_cmd, TMP_CERT, TMP_INT_CACNF, TMP_CERTREQ))
                iferrorlogandexit(
                    "Unable to create est SUDI Int Lvl %d certificate" % (i), 1)
            system("%s x509 -sha256 -in %s -text" % (openssl_cmd, TMP_CERT))
            os.environ["COUNT"] = "%d-%d" % (CHAIN_NUM, i)
            TMP_CACERT = TMP_CERT
            TMP_CAPRIVKEY = TMP_PRIVKEY
            with open(CHAIN_FILE, "a") as outfile:
                with open(TMP_CACERT) as infile:
                    outfile.write(infile.read())
        print(msg_endpnt_crt)
        system("%s req -new -sha256 -nodes -out %s %s -keyout %s -subj %s -config %s" %
               (openssl_cmd, TMP_CERTREQ, TMP_NEWKEY_CMD, TMP_FINAL_PRIVKEY, TMP_FINAL_SUBJ, TMP_FINAL_CACNF))
        iferrorlogandexit("Unable to create est server CSR", 1)
        print(TMP_FINAL_CERT)
        system("%s ca -md sha256 -out %s -batch -config %s -extfile %s -infiles %s" %
               (openssl_cmd, TMP_FINAL_CERT, TMP_FINAL_CACNF, EXT_FILE, TMP_CERTREQ))
        iferrorlogandexit("Unable to create est server certificate", 1)
        del os.environ["COUNT"]
        system("%s x509 -sha256 -in %s -text" % (openssl_cmd, TMP_FINAL_CERT))
        combinefiles(TMP_FINAL_CERT, TMP_FINAL_PRIVKEY, TMP_CERTANDKEY)

def createCSR(outdir, keyfile, subj_line, configfile):
    system("%s req -new -sha256 -nodes -out %s -key %s -subj \"%s\" -config %s" %
           (openssl_cmd, outdir, keyfile, subj_line, configfile))
    iferrorlogandexit(
        "Unable to create CSR for %s" % (subj_line), 1)
