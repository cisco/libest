/*------------------------------------------------------------------
 * util.c - Utilities used by all the unit test code 
 *
 * June, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "NonPosix.h"
#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#endif

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

    *contents = (unsigned char *)malloc(len + 1);
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

/*
 * This function simply opens a TCP connection using
 * the BIO interface.
 */
// TODO merge this with EST_ERROR est_client_connect (EST_CTX *ctx, SSL **ssl)
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
        // printf("established connection");
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

/*
 * This function simply opens a TCP connection using
 * the BIO interface. This only works for IPv4
 */
// TODO merge this with EST_ERROR est_client_connect (EST_CTX *ctx, SSL **ssl)
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
    int i;

    fflush(stdout);
    printf("\ndumpbin (%d bytes):\n", (int)len);
    for (i = 0; i < (int)len; i++) {
        /*if (buf[i] >= 0xA)*/ printf("%c", buf[i]);
        //if (i%32 == 31) printf("\n");
    }
    printf("\n");
    fflush(stdout);
}


