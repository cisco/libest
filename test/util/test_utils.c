/*------------------------------------------------------------------
 * util.c - Utilities used by all the unit test code 
 *
 * June, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif 
#include <string.h>
#include <stdlib.h>
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
    keyin = BIO_new(BIO_s_file_internal());
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
    keyin = BIO_new(BIO_s_file_internal());
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

