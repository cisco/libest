/*------------------------------------------------------------------
 * curl_utils.c - Client HTTP operation utilities that utilize
 *                libcurl.
 *
 * June, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <string.h>
#include <curl/curl.h>

/*
 * This function uses libcurl to send a simple HTTP GET
 * request with no Content-Type header.
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * url:	    char array containing the full server name and path
 * cacert:  char array with the path name of the CA certs file
 *	    on the local file system.
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
long curl_http_get (char *url, char *cacert, void *writefunc)
{
  long http_code = 0;
  CURL *hnd;

  /*
   * Setup Curl 
   */
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_CAINFO, cacert);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);
  /*
   * If the caller wants the HTTP data from the server
   * set the callback function
   */
  if (writefunc) {
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
  }

  /*
   * Send the HTTP GET request
   */
  curl_easy_perform(hnd);

  /*
   * Get the HTTP reponse status code from the server
   */
  curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;

  return (http_code);
}

/*
 * This function uses libcurl to send an HTTP POST request to
 * a given URL.  The parameters are:
 *
 * url:	    char array containing the full server name and path
 * ct:	    char array specifying the HTTP Content Type header to use
 * data:    binary data to post to the server
 * uidpwd:  char array containing the User ID and Password to be used
 *	    for HTTP authentication.  Use a colin to delimit the
 *	    two fields.
 * cacert:  char array with the path name of the CA certs file
 *	    on the local file system.  This is optional.  Pass NULL
 *	    to disable TLS verification of the peer's certificate,
 *	    which may be valid for some TLS-SRP use cases.
 * authmode:  Libcurl authentication mode to use.  Should be
 *            CURLAUTH_DIGEST or CURLAUTH_BASIC
 * cipher_suite: char array containing list of TLS cipher suites to enable
 *               in the TLS stack.  The naming convention follows
 *               OpenSSL.  This parameter is optional.  Pass in NULL
 *               to use the default cipher list.
 * srp_user: User name to use for TLS-SRP authentication
 * srp_pwd: Password to use for TLS-SRP authentication
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 * hdrfunc: Function pointer to handle writing the data
 *          from the HTTP header received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
long curl_http_post_srp (char *url, char *ct, char *data, 
	                 char *uidpwd, char *cacert, long authmode,
		         char *cipher_suite,
			 char *srp_user, char *srp_pwd,
		         void *writefunc,
		         void *hdrfunc)
{
  long http_code = 0;
  CURL *hnd;
  struct curl_slist *slist1;


  /*
   * Set the Content-Type header in the HTTP request 
   */
  slist1 = NULL;
  slist1 = curl_slist_append(slist1, ct);
  slist1 = curl_slist_append(slist1, "Connection: close");

  /*
   * Setup all the other fields that CURL requires
   */
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_USERPWD, uidpwd);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.41.0");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_HTTPAUTH, authmode);
  curl_easy_setopt(hnd, CURLOPT_TLSAUTH_USERNAME, srp_user);
  curl_easy_setopt(hnd, CURLOPT_TLSAUTH_PASSWORD, srp_pwd);
  curl_easy_setopt(hnd, CURLOPT_SSL_ENABLE_ALPN, 0L);
  if (cacert) {
    curl_easy_setopt(hnd, CURLOPT_CAINFO, cacert);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
  } else {
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);
  }
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);
  if (cipher_suite) {
    curl_easy_setopt(hnd, CURLOPT_SSL_CIPHER_LIST, cipher_suite);
  }

  /*
   * If the caller wants the HTTP data from the server
   * set the callback function
   */
  if (writefunc) {
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
  }
  if (hdrfunc) {
    curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, hdrfunc);
  }

  /*
   * Issue the HTTP request
   */
  curl_easy_perform(hnd);

  /*
   * Get the HTTP reponse status code from the server
   */
  curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist1);
  slist1 = NULL;

  return (http_code);
}

/*
 * This function uses libcurl to send an HTTP POST request to
 * a given URL.  The parameters are:
 *
 * url:	    char array containing the full server name and path
 * ct:	    char array specifying the HTTP Content Type header to use
 * data:    binary data to post to the server
 * uidpwd:  char array containing the User ID and Password to be used
 *	    for HTTP authentication.  Use a colin to delimit the
 *	    two fields.
 * cacert:  char array with the path name of the CA certs file
 *	    on the local file system.
 * authmode:  Libcurl authentication mode to use.  Should be
 *            CURLAUTH_DIGEST or CURLAUTH_BASIC
 * cipher_suite: char array containing list of TLS cipher suites to enable
 *               in the TLS stack.  The naming convention follows
 *               OpenSSL.  This parameter is optional.  Pass in NULL
 *               to use the default cipher list.
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 * hdrfunc: Function pointer to handle writing the data
 *          from the HTTP header received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
long curl_http_post (char *url, char *ct, char *data, 
	             char *uidpwd, char *cacert, long authmode,
		     char *cipher_suite,
		     void *writefunc,
		     void *hdrfunc)
{
  long http_code = 0;
  CURL *hnd;
  struct curl_slist *slist1;

  /*
   * Set the Content-Type header in the HTTP request 
   */
  slist1 = NULL;
  slist1 = curl_slist_append(slist1, ct);
  slist1 = curl_slist_append(slist1, "Connection: close");

  /*
   * Setup all the other fields that CURL requires
   */
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_USERPWD, uidpwd);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_HTTPAUTH, authmode);
  curl_easy_setopt(hnd, CURLOPT_CAINFO, cacert);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);
  if (cipher_suite) {
    curl_easy_setopt(hnd, CURLOPT_SSL_CIPHER_LIST, cipher_suite);
  }

  /*
   * If the caller wants the HTTP data from the server
   * set the callback function
   */
  if (writefunc) {
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
  }
  if (hdrfunc) {
    curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, hdrfunc);
  }

  /*
   * Issue the HTTP request
   */
  curl_easy_perform(hnd);

  /*
   * Get the HTTP reponse status code from the server
   */
  curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist1);
  slist1 = NULL;

  return (http_code);
}

/*
 * This function uses libcurl to send an HTTP POST request to
 * a given URL.  The parameters are:
 *
 * url:	    char array containing the full server name and path
 * ct:	    char array specifying the HTTP Content Type header to use
 * data:    binary data to post to the server
 * certfile: char array containing full path name of file containing
 *           PEM encoded X509 certificate to use for the TLS client
 *           authentication
 * keyfile: char array containing full path name of the file containing
 *          PEM encoded private key associated with the client cert.
 * cacert:  char array with the path name of the CA certs file
 *	    on the local file system.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
long curl_http_post_cert (char *url, char *ct, char *data, 
	                  char *certfile, char *keyfile, 
			  char *cacert, void *writefunc)
{
  long http_code = 0;
  CURL *hnd;
  struct curl_slist *slist1;

  /*
   * Set the Content-Type header in the HTTP request 
   */
  slist1 = NULL;
  slist1 = curl_slist_append(slist1, ct);
  slist1 = curl_slist_append(slist1, "Connection: close");

  /*
   * Setup all the other fields that CURL requires
   */
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_CAINFO, cacert);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt(hnd, CURLOPT_SSLCERT, certfile);
  curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
  curl_easy_setopt(hnd, CURLOPT_SSLKEY, keyfile);
  curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);

  /*
   * Issue the HTTP request
   */
  curl_easy_perform(hnd);

  /*
   * Get the HTTP reponse status code from the server
   */
  curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist1);
  slist1 = NULL;

  return (http_code);
}


/*
 * This function uses libcurl to send an HTTP POST request to a given URL.  As
 * with the function above, it uses only the cert as the authentication, there
 * is no HTTP Auth.  The only diffference here is that, this version takes in
 * theheader write function in addition to the data write function, so that
 * they can both be accessed by the calling function.  The parameters are:
 *
 * url:	    char array containing the full server name and path
 * ct:	    char array specifying the HTTP Content Type header to use
 * data:    binary data to post to the server
 * certfile: char array containing full path name of file containing
 *           PEM encoded X509 certificate to use for the TLS client
 *           authentication
 * keyfile: char array containing full path name of the file containing
 *          PEM encoded private key associated with the client cert.
 * cacert:  char array with the path name of the CA certs file
 *	    on the local file system.
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 * hdrfunc: Function pointer to handle writing the data
 *          from the HTTP header received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
long curl_http_post_cert_write (char *url, char *ct, char *data, 
                                char *certfile, char *keyfile, 
                                char *cacert, void *writefunc,
                                void *hdrfunc)
{
  long http_code = 0;
  CURL *hnd;
  struct curl_slist *slist1;

  /*
   * Set the Content-Type header in the HTTP request 
   */
  slist1 = NULL;
  slist1 = curl_slist_append(slist1, ct);
  slist1 = curl_slist_append(slist1, "Connection: close");

  /*
   * Setup all the other fields that CURL requires
   */
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_CAINFO, cacert);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt(hnd, CURLOPT_SSLCERT, certfile);
  curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
  curl_easy_setopt(hnd, CURLOPT_SSLKEY, keyfile);
  curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);

  /*
   * If the caller wants the HTTP data from the server
   * set the callback function
   */
  if (writefunc) {
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
  }
  if (hdrfunc) {
    curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, hdrfunc);
  }
  
  /*
   * Issue the HTTP request
   */
  curl_easy_perform(hnd);

  /*
   * Get the HTTP reponse status code from the server
   */
  curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist1);
  slist1 = NULL;

  return (http_code);
}


/*
 * This function uses libcurl to send an HTTP POST request to
 * a given URL.  The parameters are:
 *
 * url:	    char array containing the full server name and path
 * ct:	    char array specifying the HTTP Content Type header to use
 * data:    binary data to post to the server
 * uidpwd:  char array containing the User ID and Password to be used
 *	    for HTTP authentication.  Use a colin to delimit the
 *	    two fields.
 * certfile: char array containing full path name of file containing
 *           PEM encoded X509 certificate to use for the TLS client
 *           authentication
 * keyfile: char array containing full path name of the file containing
 *          PEM encoded private key associated with the client cert.
 * cacert:  char array with the path name of the CA certs file
 *	    on the local file system.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
long curl_http_post_certuid (char *url, char *ct, char *data, 
	                     char *uidpwd, 
	                     char *certfile, char *keyfile, 
			     char *cacert, void *writefunc)
{
  long http_code = 0;
  CURL *hnd;
  struct curl_slist *slist1;

  /*
   * Set the Content-Type header in the HTTP request 
   */
  slist1 = NULL;
  slist1 = curl_slist_append(slist1, ct);
  slist1 = curl_slist_append(slist1, "Connection: close");

  /*
   * Setup all the other fields that CURL requires
   */
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
  curl_easy_setopt(hnd, CURLOPT_USERPWD, uidpwd);
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_CAINFO, cacert);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt(hnd, CURLOPT_SSLCERT, certfile);
  curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
  curl_easy_setopt(hnd, CURLOPT_SSLKEY, keyfile);
  curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TIMEOUT, 30L);

  /*
   * Issue the HTTP request
   */
  curl_easy_perform(hnd);

  /*
   * Get the HTTP reponse status code from the server
   */
  curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist1);
  slist1 = NULL;

  return (http_code);
}

/*
 * This function uses libcurl to send a simple HTTP GET
 * request with no Content-Type header.
 * Content header supplied by caller.
 * This request will also take a parm that will become a
 * custom request instead of GET or POST (e.g. MYREQUEST)
 *
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * url:	    char array containing the full server name and path
 * cacert:  char array with the path name of the CA certs file
 *	    on the local file system.
 * myrequest: char array with a custom command name such as PUT, etc
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
long curl_http_custom (char *url, char *cacert, char *myrequest, void *writefunc)
{
  long http_code = 0;
  CURL *hnd;

  /*
   * Setup Curl 
   */
  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_CAINFO, cacert);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, myrequest);

  printf("\ncurl_utils.c: Here is the custom request: %s\n", myrequest);

  /*
   * If the caller wants the HTTP data from the server
   * set the callback function
   */
  if (writefunc) {
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
  }

  /*
   * Send the HTTP GET request
   */
  curl_easy_perform(hnd);

  /*
   * Get the HTTP reponse status code from the server
   */
  curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;

  return (http_code);
}


