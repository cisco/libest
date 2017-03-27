
/** @file */
/*------------------------------------------------------------------
 * est/est_client_proxy.c - EST client proxy mode code
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

#include <stdio.h>
#include <sys/types.h>
#ifdef WIN32
// Watch out! winsock2 and friends has to be ahead of most things
#   include <winsock2.h>
#   include <Ws2tcpip.h>
#else
#   include <sys/socket.h>
#   include <netdb.h>
#   include <unistd.h>
#   include <arpa/inet.h>
#endif /* WIN32 */
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "est_client_proxy.h"
#include "est.h"
#include "est_locl.h"

#ifdef WIN32
    /* _snprintf on Windows does not NULL-terminate when the output is
     * truncated. That's fine in this file as we reject truncated strings. */
#   define snprintf _snprintf
#endif

#define TCW_URL_SCHEMA_PORT_SIZE 50

/* Use WSAAddressToStringA instead of inet_ntop on Windows as inet_ntop does not
 * exist on Windows XP.
 * Can't use `const struct sockaddr *` here because WSAAddressToStringA takes
 * a LPSOCKADDR.
 */
static int addr_to_str (struct sockaddr *addr, char *str, size_t str_size,
                        unsigned short int *port)
{
    int ret = -1;
#ifdef WIN32
    DWORD dw_str_size;
    size_t addr_len = 0;

    switch (addr->sa_family) {
        case AF_INET:
            addr_len = sizeof(struct sockaddr_in);
            *port = ntohs(((struct sockaddr_in *)addr)->sin_port);
            break;
        case AF_INET6:
            addr_len = sizeof(struct sockaddr_in6);
            *port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
            break;
        default:
            break;
    }
    dw_str_size = str_size;
    if (addr_len != 0 &&
            WSAAddressToStringW(addr, addr_len, NULL, (LPWSTR)str, &dw_str_size) == 0) {
        ret = 0;
    }
#else
    switch (addr->sa_family) {
        case AF_INET:
            *port = ntohs(((struct sockaddr_in *)addr)->sin_port);
            if (inet_ntop(addr->sa_family,
                    &((struct sockaddr_in *)addr)->sin_addr,
                    str,
                    str_size)) {
                ret = 0;
            }
            break;
        case AF_INET6:
            *port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
            if (inet_ntop(addr->sa_family,
                    &((struct sockaddr_in6 *)addr)->sin6_addr,
                    str,
                    str_size)) {
                ret = 0;
            }
            break;
        default:
            break;
    }
#endif

    return ret;
}

static tcw_err_t tcw_direct_close (tcw_sock_t *sock)
{
    tcw_err_t ret = TCW_OK;

    if (CLOSE_SOCKET(sock->sock_fd) != 0) {
        EST_LOG_ERR("close failed: %d", GET_SOCK_ERR());
        ret = TCW_ERR_CLOSE;
        /* SOCK_ERR already set */
        goto done;
    }
    sock->sock_fd = SOCK_INVALID;

done:
    return ret;
}

/*
 * Establish a direct socket connection with the EST server using
 * normal system calls
 */
static tcw_err_t tcw_direct_connect (tcw_sock_t *sock, tcw_opts_t *opts,
                                      const char *host, unsigned short int port)
{
    tcw_err_t ret = TCW_OK;
    struct addrinfo *addrs = NULL;
    struct addrinfo *cur_addr;
    SOCK_TYPE fd;
    int err;
    int saved_err;
    char port_str[10];
    char sock_addr_str[INET6_ADDRSTRLEN];
    unsigned short int sock_port;
    struct addrinfo hints = { 0 };
    int n;

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_ADDRCONFIG;

    n = snprintf(port_str, sizeof(port_str), "%hu", port);
    if (n < 0 || n >= (int)sizeof(port_str)) {
        errno = ENOMEM;
        ret = TCW_ERR_ALLOC;
        goto done;
    }
    EST_LOG_INFO("getaddrinfo(%s, %s)", host, port_str);
    if ((err = getaddrinfo(host, port_str, &hints, &addrs)) != 0) {
        EST_LOG_ERR("getaddrinfo returned %d: %s", err, gai_strerror(err));
        ret = TCW_ERR_RESOLV;
#ifdef WIN32
        /* SOCK_ERR already set */
#else
        switch (err) {
            case EAI_SYSTEM:
                /* SOCK_ERR already set */
                break;
            case EAI_MEMORY:
                SET_SOCK_ERR_NOMEM();
                break;
            default:
                /* Could not resolve host */
                SET_SOCK_ERR_NONAME();
                break;
        }
#endif
        goto done;
    }
    cur_addr = addrs;
    while (cur_addr) {
        ret = TCW_OK;
        fd = socket(cur_addr->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            EST_LOG_WARN("socket failed: %d", GET_SOCK_ERR());
            ret = TCW_ERR_SOCKET;
            cur_addr = cur_addr->ai_next;
            continue;
        }

        err = addr_to_str(cur_addr->ai_addr, sock_addr_str, sizeof(sock_addr_str),
                          &sock_port);
        if (!err) {
            EST_LOG_INFO("connect(%s port %hu)", sock_addr_str, sock_port);
        }
        if (connect(fd, cur_addr->ai_addr, cur_addr->ai_addrlen) < 0) {
            EST_LOG_WARN("connect failed: %d", GET_SOCK_ERR());
            ret = TCW_ERR_CONNECT;
            /* CLOSE_SOCKET() may clobber SOCK_ERR */
            saved_err = GET_SOCK_ERR();
            CLOSE_SOCKET(fd);
            fd = SOCK_INVALID;
            SET_SOCK_ERR(saved_err);
            cur_addr = cur_addr->ai_next;
            continue;
        }
        break;
    }
    if (fd >= 0) {
        sock->sock_fd = fd;
    } else {
        EST_LOG_ERR("Could not connect to %s:%hu", host, port);
        /* ret and SOCK_ERR already set */
    }
done:
    return ret;
}

#ifdef HAVE_LIBCURL
static tcw_err_t tcw_curl_close (tcw_sock_t *sock)
{
    tcw_err_t ret = TCW_OK;

    if (sock->curl_handle) {
        curl_easy_cleanup(sock->curl_handle);
    }
    sock->curl_handle = NULL;
    sock->sock_fd = SOCK_INVALID;

    return ret;
}


static tcw_err_t set_blocking_mode (tcw_sock_t *sock, int blocking)
{
    tcw_err_t ret = TCW_OK;

#ifdef WIN32
    int result;
    unsigned long mode = blocking ? 0 : 1;

    result = ioctlsocket(sock->sock_fd, FIONBIO, &mode);
    if (result != NO_ERROR) {
        /*
         * As per:
         * https://msdn.microsoft.com/en-us/library/windows/desktop/ms740126(v=vs.85).aspx
         *
         * Ioctl and Ioctlsocket/WSAIoctl
         *
         * Various C language run-time systems use the IOCTLs for purposes
         * unrelated to Windows Sockets. As a consequence, the ioctlsocket
         * function and the WSAIoctl function were defined to handle socket
         * functions that were performed by IOCTL and fcntl in the Berkeley
         * Software Distribution.
         *
         * Since ioctlsocket is the Windows equivalent of ioctl/fcntl, just
         * set return type accordingly.
         */
        ret = TCW_ERR_FCNTL;
        goto done;
    }
#else
    int flags = fcntl(sock->sock_fd, F_GETFL);
    if (flags < 0) {
        EST_LOG_ERR("fcntl(F_GETFL) failed: %d", GET_SOCK_ERR());
        /* SOCK_ERR is already set */
        ret = TCW_ERR_FCNTL;
        goto done;
    }
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    if (fcntl(sock->sock_fd, F_SETFL, flags) < 0) {
        EST_LOG_ERR("fcntl(F_SETFL) failed: %d", GET_SOCK_ERR());
        /* SOCK_ERR is already set */
        ret = TCW_ERR_FCNTL;
        goto done;
    }
#endif /* WIN32 */

done:
    return ret;
}

/*
 * Establish a socket with the remote server using libcurl. Do not have it
 * actually send a URL. Leverage libcurl's proxy support to just establish
 * the connection.
 */
static tcw_err_t tcw_curl_connect (tcw_sock_t *sock, tcw_opts_t *opts,
                                   const char *host, unsigned short int port)
{
    tcw_err_t ret = TCW_OK;
    size_t url_size;
    char *url = NULL;
    CURLcode curlcode;
    long curl_socket;
    long auth_bits;
    long proxy_type = -1;
    int saved_err;
    const char *proxy_type_str = "NONE";
    int n;

    sock->curl_handle = curl_easy_init();
    if (!sock->curl_handle) {
        EST_LOG_ERR("curl_easy_init failed");
        errno = ENOMEM;
        ret = TCW_ERR_ALLOC;
        goto done;
    }
    /*
     * All we want libcurl to do here is establish the connection to
     * the proxy server.  Once that's done we'll use the socket
     * as we normally do on a direct connect to the EST server
     */
    curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_CONNECT_ONLY, 1);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_setopt(CURLOPT_CONNECT_ONLY) returned %d: %s",
                    curlcode, curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }
    url_size = strlen(host) + TCW_URL_SCHEMA_PORT_SIZE;
    url = (char *)calloc(1, url_size);
    if (!url) {
        EST_LOG_ERR("calloc failed");
        errno = ENOMEM;
        ret = TCW_ERR_ALLOC;
        goto done;
    }
    /*
     * "http" here is telling libcurl not to wrap whatever data we send in
     *  SSL. 
     */
    n = snprintf(url, url_size-1, "http://%s:%hu", host, port);
    if (n < 0 || n >= (int)url_size) {
        errno = ENOMEM;
        ret = TCW_ERR_ALLOC;
        goto done;
    }
    curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_URL, url);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_setopt(CURLOPT_URL) returned %d: %s", curlcode,
                    curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }

    /*
     * proxy host and port
     */
    curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_PROXY, opts->proxy_host);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_setopt(CURLOPT_PROXY) returned %d: %s", curlcode,
                    curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }
    curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_PROXYPORT, opts->proxy_port);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_setopt(CURLOPT_PROXYPORT) returned %d: %s", curlcode,
                    curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }

    /*
     * proxy protocol including HTTP tunnel mode
     */
    if (opts->proxy_proto == EST_CLIENT_PROXY_HTTP_NOTUNNEL) {
        proxy_type = CURLPROXY_HTTP;
        proxy_type_str = "HTTP (no tunneling)";
    } else if (opts->proxy_proto == EST_CLIENT_PROXY_HTTP_TUNNEL) {
        proxy_type = CURLPROXY_HTTP;
        proxy_type_str = "HTTP (tunneling)";
    } else if (opts->proxy_proto == EST_CLIENT_PROXY_SOCKS4) {
        proxy_type = CURLPROXY_SOCKS4;
        proxy_type_str = "SOCKS4";
    } else if (opts->proxy_proto == EST_CLIENT_PROXY_SOCKS5) {
        proxy_type = CURLPROXY_SOCKS5;
        proxy_type_str = "SOCKS5";
    } else if (opts->proxy_proto == EST_CLIENT_PROXY_SOCKS4A) {
        proxy_type = CURLPROXY_SOCKS4A;
        proxy_type_str = "SOCKS4A";
    } else if (opts->proxy_proto == EST_CLIENT_PROXY_SOCKS5_HOSTNAME) {
        proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
        proxy_type_str = "SOCKS5_HOSTNAME";
    }
    curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_PROXYTYPE, proxy_type);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_setopt(CURLOPT_PROXYTYPE) returned %d: %s",
                    curlcode, curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }
    if (opts->proxy_proto == EST_CLIENT_PROXY_HTTP_TUNNEL) {
        curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_HTTPPROXYTUNNEL, 1);
        if (curlcode != CURLE_OK) {
            EST_LOG_ERR("curl_easy_setopt(CURLOPT_HTTPPROXYTUNNEL) returned %d: %s",
                        curlcode, curl_easy_strerror(curlcode));
            errno = EINVAL;
            ret = TCW_ERR_OTHER;
            goto done;
        }
    }

    curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_PROXYAUTH, CURLAUTH_BASIC|CURLAUTH_ONLY);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_setopt(CURLOPT_PROXYAUTH) returned %d: %s",
                    curlcode, curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }

    /*
     * username and password
     */
    if (opts->proxy_username && opts->proxy_password) {
        curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_PROXYUSERNAME,
                                    opts->proxy_username);
        if (curlcode != CURLE_OK) {
            EST_LOG_ERR("curl_easy_setopt(CURLOPT_PROXYUSERNAME) returned %d: %s",
                        curlcode, curl_easy_strerror(curlcode));
            errno = EINVAL;
            ret = TCW_ERR_OTHER;
            goto done;
        }
        curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_PROXYPASSWORD,
                                    opts->proxy_password);
        if (curlcode != CURLE_OK) {
            EST_LOG_ERR("curl_easy_setopt(CURLOPT_PROXYPASSWORD) returned %d: %s",
                        curlcode, curl_easy_strerror(curlcode));
            errno = EINVAL;
            ret = TCW_ERR_OTHER;
            goto done;
        }
        auth_bits = 0;
        if (opts->proxy_auth & EST_CLIENT_PROXY_AUTH_BASIC) {
            auth_bits |= CURLAUTH_BASIC;
        }
        if (opts->proxy_auth & EST_CLIENT_PROXY_AUTH_NTLM) {
            auth_bits |= CURLAUTH_NTLM;
        }
        if (auth_bits) {
            curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_PROXYAUTH, auth_bits);
            if (curlcode != CURLE_OK) {
                EST_LOG_ERR("curl_easy_setopt(CURLOPT_PROXYAUTH) returned %d: %s",
                            curlcode, curl_easy_strerror(curlcode));
                errno = EINVAL;
                ret = TCW_ERR_OTHER;
                goto done;
            }
        }
    }

    /*
     * no signals generated from libcurl
     */
    curlcode = curl_easy_setopt(sock->curl_handle, CURLOPT_NOSIGNAL, 1);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_setopt(CURLOPT_NOSIGNAL) returned %d: %s",
                    curlcode, curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }

    /*
     * perform the curl request
     */
    EST_LOG_INFO("curl_easy_perform(%s), proxy type %s", url, proxy_type_str);
    curlcode = curl_easy_perform(sock->curl_handle);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_perform(%s) returned %d: %s", url, curlcode,
                    curl_easy_strerror(curlcode));
        if (curlcode == CURLE_COULDNT_RESOLVE_PROXY ||
            curlcode == CURLE_COULDNT_RESOLVE_HOST) {
            SET_SOCK_ERR_NONAME();
            ret = TCW_ERR_RESOLV;
            goto done;
        } else {
            SET_SOCK_ERR_CONN();
            ret = TCW_ERR_CONNECT;
            goto done;
        }
    }

    /*
     * retrieve the socket from libcurl
     */
    curlcode = curl_easy_getinfo(sock->curl_handle, CURLINFO_LASTSOCKET,
                                 &curl_socket);
    if (curlcode != CURLE_OK) {
        EST_LOG_ERR("curl_easy_getinfo(CURLINFO_LASTSOCKET) returned %d: %s",
                    curlcode, curl_easy_strerror(curlcode));
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }
    if (curl_socket == -1) {
        EST_LOG_ERR("CURLINFO_LASTSOCKET: invalid socket");
        errno = EINVAL;
        ret = TCW_ERR_OTHER;
        goto done;
    }
    sock->sock_fd = curl_socket;

    /* after connection is made, set socket to blocking */
    ret = set_blocking_mode(sock, 1);
    if (ret != TCW_OK) {
        /* SOCK_ERR is already set */
        EST_LOG_ERR("Failed to set socket to blocking");
        goto done;
    }

  done:
    free(url);
    url = NULL;
    if (ret != TCW_OK) {
        saved_err = GET_SOCK_ERR();
        tcw_curl_close(sock);
        SET_SOCK_ERR(saved_err);
    }

    return ret;
}
#endif

/*
 * entry point to establish a connection with the remote EST server
 */
tcw_err_t tcw_connect (tcw_sock_t *sock, tcw_opts_t *opts, const char *host,
                       unsigned short int port, SOCK_TYPE *sock_fd)
{
    tcw_err_t ret = TCW_OK;

    memset(sock, 0, sizeof(tcw_sock_t));
    sock->sock_fd = SOCK_INVALID;

    sock->proxy_proto = opts->proxy_proto;
    if (sock->proxy_proto != EST_CLIENT_PROXY_NONE) {
#ifdef HAVE_LIBCURL
        ret = tcw_curl_connect(sock, opts, host, port);
#else
        /*
         * We should not make it this far, but if we do,
         * log a message as to why this is wrong and return
         */
        EST_LOG_ERR("Proxy settings currently require libcurl");
        errno = EINVAL;
        ret = TCW_ERR_ARG;
        goto done;
#endif
    } else {
        ret = tcw_direct_connect(sock, opts, host, port);
    }
    if (ret != TCW_OK) {
        goto done;
    }
    EST_LOG_INFO("Successfully connected to %s:%hu", host, port);
    *sock_fd = sock->sock_fd;

done:
    return ret;
}

tcw_err_t tcw_close (tcw_sock_t *sock)
{
    tcw_err_t ret = TCW_OK;

    if (sock->proxy_proto == EST_CLIENT_PROXY_NONE) {
        ret = tcw_direct_close(sock);
    } else {
#ifdef HAVE_LIBCURL
        ret = tcw_curl_close(sock);
#endif
    }

    return ret;
}
