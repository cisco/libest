/** @file */
/*------------------------------------------------------------------
 * est/est_client_proxy.h - Private definitions for Client proxy
 *                          support
 *
 *
 * March, 2016
 *
 * Copyright (c) 2016, 2017 by cisco Systems, Inc.
 * All rights reserved.
 *
 * crdaviso@cisco.com
 * 2016-03-02 
 **------------------------------------------------------------------
 */

#ifndef TCP_CLI_WRAP_H
#define TCP_CLI_WRAP_H

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#endif
#include <stddef.h>
#include "est.h"
#include "est_sock_compat.h"

typedef enum tcw_err {
    TCW_OK = 0,
    TCW_ERR_ARG,     /**< check errno for details */
    TCW_ERR_ALLOC,   /**< check errno for details */
    TCW_ERR_RESOLV,  /**< check GET_SOCK_ERR() for details */
    TCW_ERR_SOCKET,  /**< check GET_SOCK_ERR() for details */
    TCW_ERR_CONNECT, /**< check GET_SOCK_ERR() for details */
    TCW_ERR_FCNTL,   /**< check GET_SOCK_ERR() for details */
    TCW_ERR_CLOSE,   /**< check GET_SOCK_ERR() for details */
    TCW_ERR_OTHER,   /**< check errno for details */
} tcw_err_t;

typedef struct tcw_opts {
    EST_CLIENT_PROXY_PROTO proxy_proto;
    char *proxy_host;
    unsigned short int proxy_port;
    unsigned int proxy_auth;
    char *proxy_username;
    char *proxy_password;
} tcw_opts_t;

typedef struct tcw_sock {
#ifdef HAVE_LIBCURL
    CURL *curl_handle;
#endif
    EST_CLIENT_PROXY_PROTO proxy_proto;
    SOCK_TYPE sock_fd;
} tcw_sock_t;

tcw_err_t tcw_connect(tcw_sock_t *sock, tcw_opts_t *opts, const char *host,
                      unsigned short int port, SOCK_TYPE *fd);
tcw_err_t tcw_close(tcw_sock_t *sock);

#endif

