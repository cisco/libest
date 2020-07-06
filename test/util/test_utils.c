/*------------------------------------------------------------------
 * util.c - Utilities used by all the unit test code 
 *
 * June, 2013
 *
 * Copyright (c) 2013, 2016, 2018 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif 
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netdb.h>
#include <regex.h>
#endif 
#include <est.h>

#define EST_PRIVATE_KEY_ENC EVP_aes_128_cbc()

/*
 * Reads a file into an unsigned char array.
 * The array should not be allocated prior to calling this
 * function.  The return value is the size of the file
 * read into the array.
 */
int read_binary_file (char *filename, unsigned char **contents)
{
    FILE *fp;
    int len;

    fp = fopen(filename, "rb");
    if (!fp) {
	fprintf(stderr, "\nUnable to open %s for reading\n", filename);
	return -1;
    }

    /*
     * Determine the size of the file
     */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *contents = malloc(len + 1);
    if (!*contents) {
	fprintf(stderr, "\nmalloc fail\n");
        fclose(fp);
	return -2;
    }
    
    if (1 != fread(*contents, len, 1, fp)) {
	printf("\nfread failed\n");
        fclose(fp);
	return -2;
    }
    /*
     * put the terminator at the end of the buffer
     */
    *(*contents+len) = 0x00;    
    fclose(fp);
    return (len);
}

/*
 * Generic function to write a binary file from
 * raw data.
 */
int write_binary_file (char *filename, unsigned char *contents, int len) 
{
    FILE *fp;

    fp = fopen(filename, "wb");
    if (!fp) {
        printf("\nUnable to open %s for writing\n", filename);
        return 0;
    }
    fwrite(contents, sizeof(char), len, fp);
    fclose(fp);
    return 1;
}
#ifndef WIN32 
/*
 * This function simply opens a TCP connection using
 * the BIO interface.
 */
BIO *open_tcp_socket (char *ipaddr, char *port)
{
    BIO *tcp;
    int             sock;
    int             rc;
    struct          addrinfo hints, *ai, *aiptr;
    char            portstr[12];
    int             oval = 1;
    /*
     * Unfortunately the OpenSSL BIO socket interface doesn't
     * support IPv6.  This precludes us from using BIO_do_connect().
     * We'll need to open a raw socket ourselves and pass that to OpenSSL.
     */
    snprintf(portstr, sizeof(portstr), "%u", *port);
    memset(&hints, '\0', sizeof(hints));
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    if ((rc = getaddrinfo(ipaddr, port, &hints, &aiptr))) {
        printf("Unable to lookup hostname %s. %s",ipaddr, gai_strerror(rc));
        return 0;
    }
    /*
     * Iterate through all the addresses found that match the
     * hostname.  Attempt to connect to them.
     */
    for (ai = aiptr; ai != NULL; ai = ai->ai_next)              {
        /*
         * Open a socket with this remote address
         */
        if ((sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 ) {
            /*
             * If we can't connect, try the next address
             */
            continue;
        }
        /*
         * Enable TCP keep-alive
         */
        rc = setsockopt(sock, SOL_SOCKET,SO_KEEPALIVE, (char *)&oval, sizeof(oval));
        if (rc < 0) {
            close(sock);
            continue;
        }
        /*
         * Connect to the remote host
         */
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0 ) {
            close(sock);
            continue;
        }
        /*
         * Connection has been established. No need to try
         * any more addresses.
         */
        printf("established connection");
        break;
    }
    freeaddrinfo(aiptr);
    if (!ai) {
        printf("Unable to connect to EST server at address %s", ipaddr);
        return 0;
    }

    /*
     * Pass the socket to the BIO interface, which OpenSSL uses
     * to create the TLS session.
     */


    tcp = BIO_new_socket(sock, BIO_CLOSE);
    if (tcp == NULL) {
	fprintf(stderr, "IP connection failed\n");
	return NULL;
    }
    BIO_set_conn_port(tcp, port);
/*
    if (BIO_do_connect(tcp) <= 0) {
	fprintf(stderr, "TCP connect failed\n");
	BIO_free_all(tcp);
	return NULL;
    }
*/
    return tcp;
}
#endif 
/*
 * This function simply opens a TCP connection using
 * the BIO interface. This only works for IPv4
 */
BIO *open_tcp_socket_ipv4 (char *ipaddr, char *port)
{
    BIO *b;

    b = BIO_new_connect(ipaddr);
    if (b == NULL) {
        fprintf(stderr, "IP connection failed\n");
        return NULL;
    }
    BIO_set_conn_port(b, port);

    if (BIO_do_connect(b) <= 0) {
        fprintf(stderr, "TCP connect failed\n");
        BIO_free_all(b);
        return NULL;
    }
    return b;
}



EVP_PKEY *read_private_key(char *key_file)
{
    BIO *keyin;
    EVP_PKEY *priv_key;
    
    /* 
     * Read in the private key
     */
    keyin = BIO_new(BIO_s_file());
    if (BIO_read_filename(keyin, key_file) <= 0) {
	printf("\nUnable to read private key file %s\n", key_file);
	return(NULL);
    }
    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead. 
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (priv_key == NULL) {
	printf("\nError while reading PEM encoded private key file %s\n", key_file);
	ERR_print_errors_fp(stderr);
	return(NULL);
    }
    BIO_free(keyin);

    return (priv_key);
}


void dumpbin (char *buf, size_t len)
{
    size_t i;

    fflush(stdout);
    printf("\ndumpbin (%d bytes):\n", (int)len);
    for (i = 0; i < len; i++) {
        /*if (buf[i] >= 0xA)*/ printf("%c", buf[i]);
        //if (i%32 == 31) printf("\n");
    }
    printf("\n");
    fflush(stdout);
}

/*
* Quick function to look for 2 specific strings (regexp)
* on the same line in a text file.
* Used to mine for specific EST log messages.
* 0 = SUCCESS, 1 = FAIL
*/
int grep2(char *filename, char *string1, char *string2) {

	char line[1024];

#ifdef WIN32
	sprintf(line, "findstr /R /C:\"%s\" %s | findstr /R /C:\"%s\"",
		string1, filename, string2);
	return system(line);
#else

	int rc;
	long line_number = 1;
	FILE *fd;

	/* Allocate space for both strings */
	regex_t *regexp1 = calloc(1, sizeof(regex_t));
	if (regexp1 == NULL) {
		printf("%s: Memory Allocation FAILURE\n", __FUNCTION__);
		return 1;
	}
	regex_t *regexp2 = calloc(1, sizeof(regex_t));
	if (regexp2 == NULL) {
		printf("%s: Memory Allocation FAILURE\n", __FUNCTION__);
		free(regexp1);
		return 1;
	}

	/* Compile the regexp string */
	rc = regcomp(regexp1, string1, REG_EXTENDED | REG_NOSUB);
	if (rc) {
		printf("%s: Problems compiling 1st regexp '%s'\n",
			__FUNCTION__, string1);
		goto cleanup;
	}
	/* Compile the regexp string */
	rc = regcomp(regexp2, string2, REG_EXTENDED | REG_NOSUB);
	if (rc) {
		printf("%s: Problems compiling 2nd regexp '%s'\n",
			__FUNCTION__, string2);
		goto cleanup;
	}

	/* Open the file to perform the regexp upon */
	fd = fopen(filename, "r");
	if (fd == NULL) {
		printf("%s: Problems opening file '%s'\n", __FUNCTION__, filename);
		rc = 1;
		goto cleanup;
	}

	/* Read in the file, line-by-line */
	rc = 1;
	while (fgets(line, sizeof(line), fd)) {
		if (regexec(regexp1, line, 0, 0, 0)) {
			line_number++;
			continue;
		}
		if (regexec(regexp2, line, 0, 0, 0)) {
			line_number++;
			continue;
		}
		printf("grep[%ld]: %s", line_number, line);
		rc = 0;
		break;
	}
	fclose(fd);

	/* If no match, print out a message */
	/* This is kind of chatty, comment it out for right now
	if (rc) {
	printf("grep[NO MATCH]: '%s''%s'\n", string1, string2);
	}
	*/

	/* Return results */
cleanup:
	free(regexp1);
	free(regexp2);
	return rc;
#endif
}

/*
* Quick function to look for a specific string (regexp) in a text file.
* Used to mine for specific EST log messages.
*/
int grep(char *filename, char *string) {
	return grep2(filename, string, ".*");
}

/*
 * Helper function to load a private key from a file
 */
EVP_PKEY *read_protected_private_key(const char *key_file, pem_password_cb *cb)
{
    BIO *keyin;
    EVP_PKEY *priv_key;

    /*
     * Read in the private key
     */
    keyin = BIO_new(BIO_s_file());
    if (BIO_read_filename(keyin, key_file) <= 0) {
    printf("\nUnable to read private key file %s\n", key_file);
    return(NULL);
    }
    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead.
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, cb, NULL);
    if (priv_key == NULL) {
    printf("\nError while parsing PEM encoded private key from file %s\n", key_file);
    }
    BIO_free(keyin);

    return (priv_key);
}

int get_subj_fld_from_cert (void *cert_csr, int cert_or_csr,
                            char *name, int len)
{
    X509_NAME *subject_nm;
    BIO *out;
    BUF_MEM *bm;
    int src_len;

    /*
     * cert = 0; csr = 1
     */
    if (cert_or_csr == 1) {
        subject_nm = X509_REQ_get_subject_name((X509_REQ *)cert_csr);
    } else {
        subject_nm = X509_get_subject_name((X509*) cert_csr);
    }
    
    out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        printf("BIO_new failed");
        return(-1);
    }

    X509_NAME_print_ex(out, subject_nm, 0,
                       XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);

    /*
     * copy out the subject field buffer to be returned
     */
    BIO_get_mem_ptr(out, &bm);
    if (bm->length > len) {
        src_len = len;
    } else {
        src_len = bm->length;
    }
    memcpy(name, bm->data, src_len);

    if (bm->length < len) {
        name[bm->length] = 0;
    } else {
        name[len] = 0;
    }

    BIO_free(out);
    return 0;
}

/*
 * Function for checking to see if coap mode is supported with the current
 * build of CiscoEST.
 */
int coap_mode_supported (char *cert_key_file, char *trusted_certs_file,
                         char *cacerts_file, int test_port)
{
    EST_CTX *ectx;
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY *priv_key;
    int rv;
    int coap_rc;

    unsigned char *trustcerts = NULL;
    int trustcerts_len = 0;

    unsigned char *cacerts = NULL;
    int cacerts_len = 0;

    /*
     * Set up the EST library in server mode.  This requires a number
     * of values to be passed to est_server_init()
     */

    /*
     * The server's ID certificate.
     */
    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, cert_key_file) <= 0) {
        printf("Unable to read server certificate file %s\n", cert_key_file);
        rv = 0;
        goto end;
    }
    /*
     * Read the file, which is expected to be PEM encoded.
     */
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (x == NULL) {
        printf("Error while reading PEM encoded server certificate file %s\n",
               cert_key_file);
        rv = 0;
        goto end;
    }
    BIO_free(certin);
    certin = NULL;

    /*
     * Read in the server's private key
     */
    keyin = BIO_new(BIO_s_file());
    if (BIO_read_filename(keyin, cert_key_file) <= 0) {
        printf("Unable to read server private key file %s\n", cert_key_file);
        rv = 0;
        goto end;
    }
    /*
     * Read in the private key file, which is expected to be a PEM
     * encoded private key.
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (priv_key == NULL) {
        printf("Error while reading PEM encoded private key file %s\n",
               cert_key_file);
        rv = 0;
        goto end;
    }
    BIO_free(keyin);
    keyin = NULL;

    /*
     * CA certs to use as the trust store
     */
    trustcerts_len = read_binary_file(trusted_certs_file, &trustcerts);
    if (trustcerts_len <= 0) {
        printf("Trusted certs file %s could not be read\n", trusted_certs_file);
        rv = 0;
        goto end;
    }

    /*
     * Read in the CA certs to use as response to /cacerts responses
     */
    cacerts_len = read_binary_file(cacerts_file, &cacerts);
    if (cacerts_len <= 0) {
        printf("CA chain file %s file could not be read\n", cacerts_file);
        rv = 0;
        goto end;
    }

    /*
     * Initialize the library and get an EST context
     */
    ectx = est_server_init(trustcerts, trustcerts_len, cacerts, cacerts_len,
                           EST_CERT_FORMAT_PEM, "estrealm", x, priv_key);
    if (!ectx) {
        printf("Unable to initialize EST context.  Aborting!!!\n");
        rv = 0;
        goto end;
    }

    /*
     * Attempt to set up CoAP mode just to see if it's supported.
     * Immediately free up the context and then check the return code
     * to see what the library indicated.
     */
    coap_rc = est_server_coap_init_start(NULL, test_port);

    if (ectx)
        est_destroy(ectx);

    if (coap_rc == EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED) {
        rv = 0;
    } else {
        rv = 1;
    }
end:
    if (certin)
        BIO_free(certin);
    if (x)
        X509_free(x);
    if (keyin)
        BIO_free(keyin);
    if (priv_key)
        EVP_PKEY_free(priv_key);
    if (trustcerts)
        free(trustcerts);
    if (cacerts)
        free(cacerts);
    return rv;
}

/*
 * This function sends the kill signal to the pid specified and polls the
 * process waiting for it to die. The parameters are the pid to kill, the
 * maximum amount of time to wait for the process to die and the time to sleep
 * between polls. The function will return 0 on success, -1 on failure to send
 * the kill signal, and -2 when the poll for waiting for the process to die
 * times out.
 */
int kill_process (pid_t pid, int max_time_msec, int time_to_sleep_msec) {
    int rv;
    int kill_timeout;
    int i;

    kill_timeout = max_time_msec / time_to_sleep_msec;
    rv = kill(pid, SIGKILL);
    if (rv) {
        return -1;
    }
    /*
     * Kill with signal 0 will send a no-op signal to the process while still
     * checking the error codes during the send. This allows us to check whether
     * the process has died via a kill(pid, 0) and checking that the returned
     * error is ESRCH indicating that pid couldn't be found.
     */
    rv = kill(pid, 0);
    for(i = 0; !rv && i < kill_timeout; i++) {
        rv = kill(pid, 0);
        usleep(time_to_sleep_msec * 1000);
    }
    if (rv && errno == ESRCH) {
        return 0;
    } else {
        return -2;
    }
}

/* 
 * This function reads a certificate and private key file and fills a X509
 * (certificate) struct and EVP_PKEY (private key) struct with the data
 * contained with the files
 */
int read_x509_cert_and_key_file (char *cert_file_path, char *pkey_file_path,
                                 X509 **cert, EVP_PKEY **pkey)
{
    int failed = 0;
    BIO *certin = NULL;
    if (cert_file_path == NULL) {
        printf("\nCert file %s doesn't exist\n", cert_file_path);
        return 1;
    }
    if (pkey_file_path == NULL) {
        printf("\nKey file %s doesn't exist\n", pkey_file_path);
        return 1;
    }
    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, cert_file_path) <= 0) {
        printf("\nUnable to read client certificate file %s\n", cert_file_path);
        failed = 1;
        goto end;
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're
     * using DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    *cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (cert == NULL) {
        printf("\nError while reading PEM encoded client certificate file %s\n",
               cert_file_path);
        failed = 1;
        goto end;
    }
    *pkey = read_private_key(cert_file_path);
    if (pkey == NULL) {
        printf("\nError while reading PEM encoded client key file %s\n",
               pkey_file_path);
        X509_free(*cert);
        failed = 1;
        goto end;
    }
end:
    BIO_free(certin);
    return failed;
}
