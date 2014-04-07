/*------------------------------------------------------------------
 * curl_utils.h - Client HTTP operation utilities that utilize
 *                libcurl.
 *
 * June, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef CURL_UTILS_H
#define CURL_UTILS_H

long curl_http_get(char *url, char *cacert, void *writefunc);
long curl_http_post(char *url, char *ct, char *data, 
	            char *uidpwd, char *cacert, long authmode,
		    char *cipher_suite,
		    void *writefunc,
		    void *hdrfunc);
long curl_http_post_cert(char *url, char *ct, char *data, 
	                 char *certfile, char *keyfile, 
			 char *cacert, void *writefunc);
long curl_http_post_certuid(char *url, char *ct, char *data, 
	                    char *uidpwd, 
	                    char *certfile, char *keyfile, 
			    char *cacert, void *writefunc);

#endif

