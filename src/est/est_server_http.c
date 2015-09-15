/*------------------------------------------------------------------
 * est/est_server_http.c - EST HTTP server
 *
 *			   This code is adapted from the Mongoose
 *			   HTTP server, which is licensed under the
 *			   MIT license.  The Mongoose copyright
 *			   is retained below. The original function
 *			   names have been retained to facilitate
 *			   code maintenance.
 *
 *
 * May, 2013
 *
 * Copyright (c) 2013-2014 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 ***------------------------------------------------------------------
 */

// 2015-08-13 improved TLS error handling and reporting, introducing general_ssl_error()
// 2015-08-13 improved logging; extracted wait_for_read() also used by simple_server.c
// 2014-06-25 improved logging of server main activity

// Copyright (c) 2004-2012 Sergey Lyubka
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include "est.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#if defined(_WIN32)
// #define _CRT_SECURE_NO_WARNINGS // Disable deprecation warning in VS2005
#else
#ifdef __linux__
#define _XOPEN_SOURCE 600     // For flockfile() on Linux
#endif
#define _LARGEFILE_SOURCE     // Enable 64-bit file offsets
#define __STDC_FORMAT_MACROS  // <inttypes.h> wants this for C++
#define __STDC_LIMIT_MACROS   // C++ wants that for INT64_MAX
#endif

#if defined (_MSC_VER)
#pragma warning (disable : 4127)    // conditional expression is constant: introduced by FD_SET(..)
#pragma warning (disable : 4204)    // non-constant aggregate initializer: issued due to missing C99 support
#endif

// Disable WIN32_LEAN_AND_MEAN.
// This makes windows.h always include winsock2.h
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif

#ifndef _WIN32_WCE // Some ANSI #includes are not available on Windows CE
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#endif // !_WIN32_WCE

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include "est_locl.h"
#include "est_ossl_util.h"

#include "est_server_http.h"
#include "est_server.h"

#define MONGOOSE_VERSION "3.5"
#define PASSWORDS_FILE_NAME ".htpasswd"
#define MG_BUF_LEN 8192
#define MAX_REQUEST_SIZE 16384
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

// Darwin prior to 7.0 and Win32 do not have socklen_t
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif // NO_SOCKLEN_T
#define _DARWIN_UNLIMITED_SELECT

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if !defined(SOMAXCONN)
#define SOMAXCONN 100
#endif

#if !defined(PATH_MAX)
#define PATH_MAX 4096
#endif



// Describes a string (chunk of memory).
struct vec {
    const char *ptr;
    size_t len;
};

struct file {
    int is_directory;
    time_t modification_time;
    int64_t size;
    FILE *fp;
    const char *membuf; // Non-NULL if file data is in memory
};
#define STRUCT_FILE_INITIALIZER { 0, 0, 0, NULL, NULL }


const void* mg_get_conn_ssl (struct mg_connection *conn)
{
    return conn ? conn->ssl : NULL;
}

#define MAX_SRC_ADDR 20

static void sockaddr_to_string (char *buf, size_t len,
                                const union usa *usa)
{
    buf[0] = '\0';
#if defined(USE_IPV6)
    inet_ntop(usa->sa.sa_family, usa->sa.sa_family == AF_INET ?
              (void*)&usa->sin.sin_addr :
              (void*)&usa->sin6.sin6_addr, buf, (socklen_t) len);
#elif defined(_WIN32)
    // Only Windoze Vista (and newer) have inet_ntop()
    strncpy(buf, inet_ntoa(usa->sin.sin_addr), len);
#else
    inet_ntop(usa->sa.sa_family, (void*)&usa->sin.sin_addr, buf, len);
#endif
}

//static void cry(struct mg_connection *conn,
//                PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);

// Print error message to the opened error log stream.
static void cry (struct mg_connection *conn, const char *fmt, ...)
{
    char buf[MG_BUF_LEN], src_addr[MAX_SRC_ADDR];
    va_list ap;
    time_t timestamp;

    va_start(ap, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    // Do not lock when getting the callback value, here and below.
    // I suppose this is fine, since function cannot disappear in the
    // same way string option can.
    conn->request_info.ev_data = buf;
    timestamp = time(NULL);

    sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
    EST_LOG_ERR("[%010lu] [error] [client %s] ", (unsigned long)timestamp, src_addr);

    if (conn->request_info.request_method != NULL) {
        EST_LOG_ERR("%s %s: ", conn->request_info.request_method, conn->request_info.uri);
    }
    EST_LOG_ERR("%s", buf);
    conn->request_info.ev_data = NULL;
}

// Return fake connection structure. Used for logging, if connection
// is not applicable at the moment of logging.
static struct mg_connection *fc (struct mg_context *ctx)
{
    static struct mg_connection fake_connection;

    fake_connection.ctx = ctx;
    return &fake_connection;
}

const char *mg_version (void)
{
    return MONGOOSE_VERSION;
}

struct mg_request_info *mg_get_request_info (struct mg_connection *conn)
{
    return &conn->request_info;
}

#if defined(_WIN32) && !defined(__MINGW32__) && !defined(__SYMBIAN32__)
static void mg_strlcpy (register char *dst, register const char *src, size_t n)
{
    for (; *src != '\0' && n > 1; n--) {
        *dst++ = *src++;
    }
    *dst = '\0';
}
#endif

static int lowercase (const char *s)
{
    return tolower(*(const unsigned char*)s);
}

static int mg_strncasecmp (const char *s1, const char *s2, size_t len)
{
    int diff = 0;

    if (len > 0) {
        do {
            diff = lowercase(s1++) - lowercase(s2++);
        } while (diff == 0 && s1[-1] != '\0' && --len > 0);
    }

    return diff;
}

static int mg_strcasecmp (const char *s1, const char *s2)
{
    int diff;

    do {
        diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0');

    return diff;
}

// Like snprintf(), but never returns negative value, or a value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
static int mg_vsnprintf (struct mg_connection *conn, char *buf, size_t buflen,
                         const char *fmt, va_list ap)
{
    int n;

    if (buflen == 0) {
        return 0;
    }

    n = vsnprintf(buf, buflen, fmt, ap);

    if (n < 0) {
        cry(conn, "vsnprintf error");
        n = 0;
    } else if (n >= (int)buflen) {
        cry(conn, "truncating vsnprintf buffer: [%.*s]",
            n > 200 ? 200 : n, buf);
        n = (int)buflen - 1;
    }
    buf[n] = '\0';

    return n;
}

#if 0
//static int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
//                       PRINTF_FORMAT_STRING(const char *fmt), ...)
//PRINTF_ARGS(4, 5);

static int mg_snprintf (struct mg_connection *conn, char *buf, size_t buflen,
                        const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = mg_vsnprintf(conn, buf, buflen, fmt, ap);
    va_end(ap);

    return n;
}
#endif

// Skip the characters until one of the delimiters characters found.
// 0-terminate resulting word. Skip the delimiter and following whitespaces.
// Advance pointer to buffer to the next word. Return found 0-terminated word.
// Delimiters can be quoted with quotechar.
char *skip_quoted (char **buf, const char *delimiters,
                   const char *whitespace, char quotechar)
{
    char *p, *begin_word, *end_word, *end_whitespace;

    begin_word = *buf;
    end_word = begin_word + strcspn(begin_word, delimiters);

    // Check for quotechar
    if (end_word > begin_word) {
        p = end_word - 1;
        while (*p == quotechar) {
            // If there is anything beyond end_word, copy it
            if (*end_word == '\0') {
                *p = '\0';
                break;
            } else {
                size_t end_off = strcspn(end_word + 1, delimiters);
                memmove(p, end_word, end_off + 1);
                p += end_off; // p must correspond to end_word - 1
                end_word += end_off + 1;
            }
        }
        for (p++; p < end_word; p++) {
            *p = '\0';
        }
    }

    if (*end_word == '\0') {
        *buf = end_word;
    } else {
        end_whitespace = end_word + 1 + strspn(end_word + 1, whitespace);

        for (p = end_word; p < end_whitespace; p++) {
            *p = '\0';
        }

        *buf = end_whitespace;
    }

    return begin_word;
}

// Simplified version of skip_quoted without quote char
// and whitespace == delimiters
char *skip (char **buf, const char *delimiters)
{
    return skip_quoted(buf, delimiters, delimiters, 0);
}


// Return HTTP header value, or NULL if not found.
static const char *get_header (const struct mg_request_info *ri,
                               const char *name)
{
    int i;

    for (i = 0; i < ri->num_headers; i++) {
        if (!mg_strcasecmp(name, ri->http_headers[i].name)) {
            return ri->http_headers[i].value;
        }
    }

    return NULL;
}

const char *mg_get_header (const struct mg_connection *conn, const char *name)
{
    return get_header(&conn->request_info, name);
}

// HTTP 1.1 assumes keep alive if "Connection:" header is not set
// This function must tolerate situations when connection info is not
// set up, for example if request parsing failed.
static int should_keep_alive (const struct mg_connection *conn)
{
    const char *http_version = conn->request_info.http_version;
    const char *header = mg_get_header(conn, "Connection");

    /*
     * Slight deviation from Mongoose behavior here.  We will close the
     * connection when sending a 202 Accepted response.  We will also
     * close the connection for any 4xx response, where Mongoose was only
     * closing for the 401 Unauthorized
     */
    if (conn->must_close ||
	conn->status_code == EST_HTTP_STAT_202 ||
        conn->status_code >= 400 ||
        !conn->ctx->enable_keepalives ||
        (header != NULL && mg_strcasecmp(header, "keep-alive") != 0) ||
        (header == NULL && http_version && strcmp(http_version, "1.1"))) {
        return 0;
    }
    return 1;
}

static const char *suggest_connection_header (const struct mg_connection *conn)
{
    return should_keep_alive(conn) ? "keep-alive" : "close";
}


#define send_http_error mg_send_http_error
void mg_send_http_error (struct mg_connection *conn, int status,
                         const char *reason, const char *fmt, ...)
{
    char buf[MG_BUF_LEN];
    va_list ap;
    int len;

    conn->status_code = status;
    conn->request_info.ev_data = (void*)(long)status;
    buf[0] = '\0';
    len = 0;

    // Errors 1xx, 204 and 304 MUST NOT send a body
    if (status > 199 && status != 204 && status != 304) {
#if 0
        len = mg_snprintf(conn, buf, sizeof(buf), "Error %d: %s\n", status, reason);
#endif

        va_start(ap, fmt);
        len += mg_vsnprintf(conn, buf + len, sizeof(buf) - len, fmt, ap);
        va_end(ap);
    }
    EST_LOG_INFO("Sending HTTP %d (%s) error response with message '%s'", status, reason, buf);

    mg_printf(conn, "HTTP/1.1 %d %s\r\n"
              "Content-Length: %d\r\n"
              "Connection: %s\r\n\r\n", status, reason, len,
              suggest_connection_header(conn));
    conn->num_bytes_sent += mg_printf(conn, "%s\r\n", buf);
}

#if defined(_WIN32) && !defined(__MINGW32__) && !defined(__SYMBIAN32__)
// For Windows, change all slashes to backslashes in path names.
static void change_slashes_to_backslashes (char *path)
{
    int i;

    for (i = 0; path[i] != '\0'; i++) {
        if (path[i] == '/') {
            path[i] = '\\';
        }
        // i > 0 check is to preserve UNC paths, like \\server\file.txt
        if (path[i] == '\\' && i > 0) {
            while (path[i + 1] == '\\' || path[i + 1] == '/') {
                (void)memmove(path + i + 1, path + i + 2, strnlen(path + i + 1, 
	                      EST_URI_MAX_LEN));
            }
        }
    }
}

// Encode 'path' which is assumed UTF-8 string, into UNICODE string.
// wbuf and wbuf_len is a target buffer and its length.
static void to_unicode (const char *path, wchar_t *wbuf, size_t wbuf_len)
{
    char buf[PATH_MAX], buf2[PATH_MAX], *p;

    mg_strlcpy(buf, path, sizeof(buf));
    change_slashes_to_backslashes(buf);

    // Point p to the end of the file name
    p = buf + strnlen(buf, EST_URI_MAX_LEN) - 1;

    // Convert to Unicode and back. If doubly-converted string does not
    // match the original, something is fishy, reject.
    memset_s(wbuf, 0, wbuf_len * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int)wbuf_len);
    WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)wbuf_len, buf2, sizeof(buf2),
                        NULL, NULL);
    if (strcmp(buf, buf2) != 0) {
        wbuf[0] = L'\0';
    }
}

// Windows happily opens files with some garbage at the end of file name.
// For example, fopen("a.cgi    ", "r") on Windows successfully opens
// "a.cgi", despite one would expect an error back.
// This function returns non-0 if path ends with some garbage.
static int path_cannot_disclose_cgi (const char *path)
{
    static const char *allowed_last_characters = "_-";
    int last = path[strnlen(path, EST_URI_MAX_LEN) - 1];

    return isalnum(last) || strchr(allowed_last_characters, last) != NULL;
}

static HANDLE dlopen (const char *dll_name, int flags)
{
    wchar_t wbuf[PATH_MAX];

    flags = 0; // Unused
    to_unicode(dll_name, wbuf, ARRAY_SIZE(wbuf));
    return LoadLibraryW(wbuf);
}
#endif // _WIN32

// Write data to the IO channel - opened file descriptor, socket or SSL
// descriptor. Return number of bytes written.
static int64_t push (FILE *fp, SOCKET sock, SSL *ssl, const char *buf,
                     int64_t len)
{
    int64_t sent;
    int n, k;

    sent = 0;
    while (sent < len) {

        // How many bytes we send in this iteration
        k = len - sent > INT_MAX ? INT_MAX : (int)(len - sent);

        if (ssl != NULL) {
            n = SSL_write(ssl, buf + sent, k);
        } else if (fp != NULL) {
            n = (int)fwrite(buf + sent, 1, (size_t)k, fp);
            if (ferror(fp)) {
                n = -1;
            }
        } else {
            n = (int) send(sock, buf + sent, (size_t)k, MSG_NOSIGNAL);
        }

        if (n < 0) {
            break;
        }

        sent += n;
    }

    return sent;
}

/* helper function also used by simple_server.c */
int wait_for_read(int sock, int usec)
{
    fd_set set;
    FD_ZERO(&set);
    FD_SET(sock, &set);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = usec;

    return select(sock + 1, &set, NULL, NULL, &tv);
}

// This function is needed to prevent Mongoose to be stuck in a blocking
// socket read when user requested exit. To do that, we sleep in select
// with a timeout, and when returned, check the context for the stop flag.
// If it is set, we return 1, and this means that we must not continue
// reading, must give up and close the connection and exit serving thread.
// On a file error, we return -(ERRNO).
static int wait_until_socket_is_readable (struct mg_connection *conn)
{
    int result;

    do {
	result = wait_for_read(conn->client.sock, 300*1000);
        if (result == 0 && conn->ssl != NULL) { // time elapsed
            result = SSL_pending(conn->ssl);
        }
    } while ((result == 0 || (result < 0 && errno == EINTR)) &&
             conn->ctx->stop_flag == 0);

    if (result < 0) {
	EST_LOG_WARN("Waiting for reading socket %d resulted in ERRNO %d (%s)",
		     conn->client.sock, errno, strerror(errno));
    }
    return (result < 0 ? -errno : (conn->ctx->stop_flag ? 1 : 0));
}

// adapted from ssl/s3_pkt.c
static int ssl_send_alert_fail (SSL *s)
{
    int level = SSL3_AL_FATAL;
    int desc = SSL_AD_HANDSHAKE_FAILURE;

    /* Map tls/ssl alert value to correct one */
    //desc=s->method->ssl3_enc->alert_value(desc);
    if (s->version == SSL3_VERSION && desc == SSL_AD_PROTOCOL_VERSION)
	desc = SSL_AD_HANDSHAKE_FAILURE; /* SSL 3.0 does not have protocol_version alerts */
    if (desc < 0) return -1;
    /* If a fatal one, remove from cache */
    if ((level == 2) && (s->session != NULL))
	SSL_CTX_remove_session(s->ctx,s->session);

    s->s3->alert_dispatch=1;
    s->s3->send_alert[0]=level;
    s->s3->send_alert[1]=desc;
    if (s->s3->wbuf.left == 0) /* data still being written out? */
	return s->method->ssl_dispatch_alert(s);
    /* else data is still being written out, we will get written
     * some time in the future */
    return -1;
}

static EST_ERROR general_ssl_error(struct mg_connection *conn, int ssl_err) {
    EST_ERROR rv = EST_ERR_SYSCALL;
    switch (ERR_peek_error()) {
    case 0:
	if (ssl_err == 0) {
	    EST_LOG_ERR("Client has disconnected violating the protocol");
	    rv = EST_ERR_SOCKET_STOP;
	}
	if (ssl_err == -1) {
	    if (errno == 0) {
		EST_LOG_WARN("TLS connection failed likely due to bad SRP username");
		rv = EST_ERR_AUTH_SRP;
	    } else {
		EST_LOG_WARN("SSL_accept resulted in ERRNO %d (%s)", errno, strerror(errno));
		if (errno == 104) { // Connection reset by peer
		    EST_LOG_WARN("Most likely the client did not accept our authentication");
		    rv = EST_ERR_AUTH_FAIL; // EST_ERR_SOCKET_STOP
		} else {
		    rv = EST_ERR_SYSCALL;
		}
	    }
	}
	break;
    case 0x0D0C5006:
	EST_LOG_ERR("Certificate/CRL signature verification failure");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x140760FC:
	EST_LOG_ERR("SSL/TLS protocol version not accepted");
	(void)ssl_send_alert_fail(conn->ssl); // In this case, make sure to stop client waiting
	break;
    case 0x140780E5:
	EST_LOG_ERR("Handshake failure; this may be due to the client not being SRP enabled");
	rv = EST_ERR_AUTH_SRP;
	break;
    case 0x14089086:
	EST_LOG_ERR("Client certificate not accepted, likely due to expiration, mismatch with trust anchor, or missing/invalid CRL");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x140890B2:
	EST_LOG_ERR("Could not get valid client certificate");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x1408A0C1:
	EST_LOG_ERR("No shared cipher");
	{
	    STACK_OF(SSL_CIPHER) *sk = SSL_get_ciphers(conn->ssl);
	    int i;
	    int len = 0;
	    for(i = 0; sk != NULL && i < sk_SSL_CIPHER_num(sk); i++) {
		SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c != NULL) {
		    len += strlen((char *)c->name)+2;
		}
	    }
	    char *list = (char *)malloc(len+1);
	    if (list != NULL) {
		list[0] = '\0';
		for(i = 0; sk != NULL && i < sk_SSL_CIPHER_num(sk); i++) {
		    SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		    if (c != NULL) {
			strcat(list, (char *)c->name);
			if (i < sk_SSL_CIPHER_num(sk)-1)
			    strcat(list, ", ");
		    }
		}
		EST_LOG_INFO("List of accepted ciphers is, in this order: %s", list);
		free(list);
	    }
	}
	rv = EST_ERR_SSL_CIPHER_LIST;
	break;
    case 0x1408F119:
	EST_LOG_ERR("Decryption failed or bad record mac; this error is likely due to bad SRP password");
	rv = EST_ERR_AUTH_SRP;
	break;
    case 0x140940E5:
	EST_LOG_ERR("SSL handshake failure");
	break;
    case 0x14094413:
	EST_LOG_WARN("This error is likely due to an invalid certificate purpose (i.e., key usage)");
	break;
    case 0x14094414:
	EST_LOG_ERR("Client certificate revoked");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x14094415:
	EST_LOG_ERR("Our certificate expired");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x14094418:
	EST_LOG_ERR("Our certificate is not accepted, likely due to expiration, mismatch with trust anchor, or missing/invalid CRL"); // OpenSSL said: "Unknown CA"
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x1409441B:
	EST_LOG_ERR("Verification error on our certificate or its CRL, SSL handshake failure");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x1409442F:
	EST_LOG_ERR("Insufficient security for SRP");
	rv = EST_ERR_AUTH_SRP;
	break;
    case 0x1409B166:
	EST_LOG_ERR("Client is trying SRP though not enabled on server");
	rv = EST_ERR_AUTH_SRP;
	break;
    default:
	ossl_dump_ssl_errors();
	break;
    }
    return rv;
}

// Read from IO channel - opened file descriptor, socket, or SSL descriptor.
// Return negative value -EST_ERR... on error, or number of bytes read on success.
static int pull (FILE *fp, struct mg_connection *conn, char *buf, int len)
{
    int nread; // or error code if negative
    int err_code;

    if (fp != NULL) {
        // Use read() instead of fread(), because if we're reading from the CGI
        // pipe, fread() may block until IO buffer is filled up. We cannot afford
        // to block and must pass all read bytes immediately to the client.
        nread = (int) read(fileno(fp), buf, (size_t)len);
	if (nread < 0)
	    nread = -EST_ERR_SSL_READ;
    } else if (!conn->must_close && (nread = wait_until_socket_is_readable(conn))) {
	return conn->ctx->stop_flag ? 0 : -EST_ERR_SOCKET/*nread*/; // nread is -ERRNO here
    } else if (conn->ssl != NULL) {
        nread = SSL_read(conn->ssl, buf, len);

	err_code = SSL_get_error(conn->ssl, nread);
	if (nread < 0) {
	    nread = -EST_ERR_SSL_READ;
	}
	if (err_code != SSL_ERROR_NONE && err_code != SSL_ERROR_WANT_READ) {
	    EST_LOG_ERR("SSL_read error: %d (%s)", err_code, ossl_error_string(err_code));
	}
	switch(err_code) {
	case SSL_ERROR_NONE:
	    /* Nothing to do, it's a graceful shutdown */
	    break;
	case SSL_ERROR_WANT_READ:
	    /*
	     * More data may be coming, change nread to zero
	     * so Mongoose will attempt to read more data
	     * from the peer.  This would occur if the peer
	     * initiated an SSL re-negotiation.
	     */
	    nread = 0;
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    ossl_dump_ssl_errors();
	    // an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.
	    break;
	case SSL_ERROR_SSL:
	    /* Some general OpenSSL error, dump the OpenSSL error log to learn more about this */
	    usleep(100); /* In case an EST_ERR_AUTH_CERT error occurred on our side, this delay helps
			    avoiding a race condition causing est_client_connect() to obtain:
			    "SSL_connect error: 5 (SSL_ERROR_SYSCALL)" with "ERRNO 104 (Connection reset by peer)"
			    This leads the client to report the too general error EST_ERR_AUTH_FAIL, 
			    while the error code should actually be the more specific EST_ERR_AUTH_CERT,
			    after reporting in the log: "SSL_connect error: 1 (SSL_ERROR_SSL)" */
	    // break;
	case SSL_ERROR_SYSCALL:
	    nread = -general_ssl_error(conn, nread); // Make sure nread is negative to indicate an error to the function above us
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    EST_LOG_WARN("Client closed connnection, possibly found a FQDN mismatch with our certificate");
	    // fall through
	default:
	    ossl_dump_ssl_errors();
	    nread = -EST_ERR_SYSCALL; // Make sure nread is negative to indicate an error to the function above us
	    break;
	}
    } else {
        nread = recv(conn->client.sock, buf, (size_t)len, 0);
	if (nread < 0)
	    nread = -EST_ERR_SSL_READ;
    }

    return conn->ctx->stop_flag ? -EST_ERR_SOCKET_STOP : nread;
}

// Return negative value -EST_ERR... on error, or number of bytes read on success.
int mg_read (struct mg_connection *conn, void *buf, size_t len)
{
    int n, buffered_len, nread;
    const char *body;

    nread = 0;
    if (conn->consumed_content < conn->content_len) {
        // Adjust number of bytes to read.
        int64_t to_read = conn->content_len - conn->consumed_content;
        if (to_read < (int64_t)len) {
            len = (size_t)to_read;
        }

        // Return buffered data
        body = conn->buf + conn->request_len + conn->consumed_content;
        buffered_len = &conn->buf[conn->data_len] - body;
        if (buffered_len > 0) {
            if (len < (size_t)buffered_len) {
                buffered_len = (int)len;
            }
            memcpy(buf, body, (size_t)buffered_len);
            len -= buffered_len;
            conn->consumed_content += buffered_len;
            nread += buffered_len;
            buf = (char*)buf + buffered_len;
        }

        // We have returned all buffered data. Read new data from the remote socket.
        while (len > 0) {
            n = pull(NULL, conn, (char*)buf, (int)len);
            if (n < 0) {
                nread = n; // Propagate the error
                break;
            } else if (n == 0) {
                break; // No more data to read
            } else {
                buf = (char*)buf + n;
                conn->consumed_content += n;
                nread += n;
                len -= n;
            }
        }
    }
    return nread;
}

int mg_write (struct mg_connection *conn, const void *buf, size_t len)
{
    int64_t total;

    total = push(NULL, conn->client.sock, conn->ssl, (const char*)buf,
                 (int64_t)len);
    return (int)total;
}

int mg_printf (struct mg_connection *conn, const char *fmt, ...)
{
    char mem[MG_BUF_LEN], *buf = mem;
    int len;
    va_list ap;

    // Print in a local buffer first, hoping that it is large enough to
    // hold the whole message
    va_start(ap, fmt);
    len = vsnprintf(mem, sizeof(mem), fmt, ap);
    va_end(ap);

    if (len == 0) {
        // Do nothing. mg_printf(conn, "%s", "") was called.
    } else if (len < 0) {
        // vsnprintf() error, give up
        len = -1;
        cry(conn, "%s(%s, ...): vsnprintf() error", __func__, fmt);
    } else if (len > (int)sizeof(mem) && (buf = (char*)malloc(len + 1)) != NULL) {
        // Local buffer is not large enough, allocate big buffer on heap
        va_start(ap, fmt);
        vsnprintf(buf, len + 1, fmt, ap);
        va_end(ap);
        len = mg_write(conn, buf, (size_t)len);
        free(buf);
    } else if (len > (int)sizeof(mem)) {
        // Failed to allocate large enough buffer, give up
        cry(conn, "%s(%s, ...): Can't allocate %d bytes, not printing anything",
            __func__, fmt, len);
        len = -1;
    } else {
        // Copy to the local buffer succeeded
        len = mg_write(conn, buf, (size_t)len);
    }

    return len;
}

// URL-decode input buffer into destination buffer.
// 0-terminate the destination buffer. Return the length of decoded data.
// form-url-encoded data differs from URI encoding in a way that it
// uses '+' as character for space, see RFC 1866 section 8.2.1
// http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
static int url_decode (const char *src, int src_len, char *dst,
                       int dst_len, int is_form_url_encoded)
{
    int i, j, a, b;

#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

    for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
        if (src[i] == '%' &&
            isxdigit(*(const unsigned char*)(src + i + 1)) &&
            isxdigit(*(const unsigned char*)(src + i + 2))) {
            a = tolower(*(const unsigned char*)(src + i + 1));
            b = tolower(*(const unsigned char*)(src + i + 2));
            dst[j] = (char)((HEXTOI(a) << 4) | HEXTOI(b));
            i += 2;
        } else if (is_form_url_encoded && src[i] == '+') {
            dst[j] = ' ';
        } else {
            dst[j] = src[i];
        }
    }

    dst[j] = '\0'; // Null-terminate the destination

    return i >= src_len ? j : -1;
}

// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
static int get_request_len (const char *buf, int buflen)
{
    const char *s, *e;
    int len = 0;

    for (s = buf, e = s + buflen - 1; len <= 0 && s < e; s++) {
        // Control characters are not allowed but >=128 is.
        if (!isprint(*(const unsigned char*)s) && *s != '\r' &&
            *s != '\n' && *(const unsigned char*)s < 128) {
            len = -1;
            break; // [i_a] abort scan as soon as one malformed character is found; don't let subsequent \r\n\r\n win us over anyhow
        } else if (s[0] == '\n' && s[1] == '\n') {
            len = (int)(s - buf) + 2;
        } else if (s[0] == '\n' && &s[1] < e &&
                   s[1] == '\r' && s[2] == '\n') {
            len = (int)(s - buf) + 3;
        }
    }

    return len;
}

// Protect against directory disclosure attack by removing '..',
// excessive '/' and '\' characters
static void remove_double_dots_and_double_slashes (char *s)
{
    char *p = s;

    while (*s != '\0') {
        *p++ = *s++;
        if (s[-1] == '/' || s[-1] == '\\') {
            // Skip all following slashes, backslashes and double-dots
            while (s[0] != '\0') {
                if (s[0] == '/' || s[0] == '\\') {
                    s++;
                } else if (s[0] == '.' && s[1] == '.') {
                    s += 2;
                } else {
                    break;
                }
            }
        }
    }
    *p = '\0';
}

#define MAX_AUTH_HDR_LEN 256
/*
 * Performs parsing of HTTP Authentication header from
 * the client when Basic authentication is used.
 */
static void mg_parse_auth_hdr_basic (struct mg_connection *conn, 
				     const char *auth_header,
	                             EST_HTTP_AUTH_HDR *ah)
{
    char *value, *s;
    char *save_ptr;
    char both[MAX_UIDPWD*2+2]; /* will contain both UID and PWD */
    int len;
    const char *sep = ":";
    
    s = (char *) auth_header + 6;

    // Gobble initial spaces
    while (isspace(*(unsigned char*)s)) {
	s++;
    }
    value = s;

    len = est_base64_decode(value, both, (MAX_UIDPWD * 2 + 2));
    if (len <= 0) {
	EST_LOG_WARN("Base64 decode of HTTP auth header failed, HTTP auth will fail");
	return;
    }

    /* Parse the username and password, which are separated by a ":" */
    value = strtok_r(both, sep, &save_ptr);
    if (value) {
	ah->user = strndup(value, MAX_UIDPWD);
        ah->pwd = strndup(save_ptr, MAX_UIDPWD);
	ah->mode = AUTH_BASIC;
    }
}

/*
 * Performs parsing of HTTP Authentication header from
 * the client when Digest authentication is used.
 */
static void mg_parse_auth_hdr_digest (struct mg_connection *conn, 
				      const char *auth_header,
	                              EST_HTTP_AUTH_HDR *ah)
{
    char *name, *value, *s;
    char buf[MAX_AUTH_HDR_LEN];
    int i;

    ah->mode = AUTH_DIGEST;

    // Make modifiable copy of the auth header
    strncpy(buf, auth_header + 7, MAX_AUTH_HDR_LEN);
    s = buf;

    // Parse authorization header
    while (1) {
        // Gobble initial spaces
        while (isspace(*(unsigned char*)s)) {
	    s++;
	}
	name = skip_quoted(&s, "=", " ", 0);
	// Value is either quote-delimited, or ends at first comma or space.
	if (s[0] == '\"') {
	    s++;
	    value = skip_quoted(&s, "\"", " ", '\\');
	    if (s[0] == ',') {
		s++;
	    }
	} else {
	    value = skip_quoted(&s, ", ", " ", 0); // IE uses commas, FF uses spaces
	}
	if (*name == '\0') {
	    break;
	}

        i = strncmp(name, "username", 8);
        if (!i) {
	    ah->user = strndup(value, MAX_UIDPWD);
	    continue;
	} 

        i = strncmp(name, "cnonce", 6);
	if (!i) {
            ah->cnonce = strndup(value, MAX_NONCE);
	    continue;
	} 

	i = strncmp(name, "response", 8);
	if (!i) {
            ah->response = strndup(value, MAX_RESPONSE);
	    continue;
        } 

	i = strncmp(name, "uri", 3);
	if (!i) {
	    ah->uri = strndup(value, MAX_REALM);
	    continue;
	} 

	i = strncmp(name, "qop", 3);
	if (!i) {
            ah->qop = strndup(value, MAX_QOP);
	    continue;
	} 

	i = strncmp(name, "nc", 2);
	if (!i) {
	    ah->nc = strndup(value, MAX_NC);
	    continue;
        } 

	i = strncmp(name, "nonce", 5); 
	if (!i) {
	    ah->nonce = strndup(value, MAX_NONCE);
	}
    }
}


/*
 * Performs parsing of HTTP Authentication header from
 * the client when Token(bearer) authentication is used.
 */
static void mg_parse_auth_hdr_token (struct mg_connection *conn, 
				     const char *auth_header,
	                             EST_HTTP_AUTH_HDR *ah)
{
    char *value, *s;
    char value_decoded[MAX_AUTH_TOKEN_LEN*2];
    int len;
    
    s = (char *) auth_header + (strlen(EST_BEARER_TOKEN_STR)-1);

    // Gobble initial spaces
    while (isspace(*(unsigned char*)s)) {
	s++;
    }

    value = s;
    memset(value_decoded, 0, MAX_AUTH_TOKEN_LEN*2);
    len = est_base64_decode(value, value_decoded, (MAX_AUTH_TOKEN_LEN*2));
    if (len <= 0) {
	EST_LOG_WARN("Base64 decode of HTTP auth credentials failed, HTTP auth will fail");
	return;
    }

    if (*s != '\0') {
        /*Copy the token into the auth header structure. */
        ah->auth_token = strndup(value_decoded, MAX_AUTH_TOKEN_LEN);
        ah->mode = AUTH_TOKEN;
        if (ah->auth_token == NULL) {
            EST_LOG_ERR("Failed to obtain memory for authentication token buffer");
        }
    } else {
	EST_LOG_ERR("Authentication header from client contained no Token");
    }   
}


/*
 * This function parses the HTTP Authentication header
 * from the client.  It will fill in the fields on the
 * EST_HTTP_AUTH_HDR struct, which are used later for
 * verifying the user's credentials using either HTTP
 * Basic or HTTP Digest authentication. The ah parameter
 * should already be allocated when calling this function.
 *
 * Return either good, bad, or missing 
 */
EST_HTTP_AUTH_HDR_RESULT mg_parse_auth_header (struct mg_connection *conn, 
                                               EST_HTTP_AUTH_HDR *ah)
{
    const char *auth_header;

    /*
     * Get the Auth header from the HTTP client 
     */
    if ((auth_header = mg_get_header(conn, "Authorization")) == NULL) {
	return EST_AUTH_HDR_MISSING;
    }

    if (mg_strncasecmp(auth_header, "Digest ", 7) == 0) {
	/* Make sure server is configured for digest auth */
	if (conn->ctx->est_ctx->auth_mode != AUTH_DIGEST) {
	    return EST_AUTH_HDR_BAD;
	}
	mg_parse_auth_hdr_digest(conn, auth_header, ah); 
    } else if (mg_strncasecmp(auth_header, "Basic ", 6) == 0) {
	/* Make sure server is configured for basic auth */
	if (conn->ctx->est_ctx->auth_mode != AUTH_BASIC) {
	    return EST_AUTH_HDR_BAD;
	}
	mg_parse_auth_hdr_basic(conn, auth_header, ah);
    } else if (mg_strncasecmp(auth_header, EST_BEARER_TOKEN_STR,
                              strlen(EST_BEARER_TOKEN_STR)) == 0) {
	/* Make sure server is configured for bearer(token) auth */
	if (conn->ctx->est_ctx->auth_mode != AUTH_TOKEN) {
	    return EST_AUTH_HDR_BAD;
	}
	mg_parse_auth_hdr_token(conn, auth_header, ah);
    } else {
	/* Only Basic, Digest and Bearer Token authentication are supported */
	ah->mode = AUTH_FAIL;
        return EST_AUTH_HDR_BAD;
    }

    /* 
     * If we're doing digest auth, make sure all the values
     * were parsed
     */
    if (ah->mode == AUTH_DIGEST && (!ah->uri ||
		                    !ah->nonce ||
				    !ah->nc ||
				    !ah->cnonce)) {
	EST_LOG_ERR("Parsing of HTTP auth header failed");
	return EST_AUTH_HDR_BAD;
    }

    /*
     * If we were not able to parse a user ID and we're not
     * in token auth mode, then make sure we fail the authentication.
     */
    if (ah->user == NULL && ah->mode != AUTH_TOKEN) {
        return EST_AUTH_HDR_BAD;
    }

    if (ah->mode != AUTH_TOKEN) {   
        /*
         * Save the user ID on the connection context.
         * We will want to pass this to the CA later.
         */
        strncpy(conn->user_id, ah->user, MG_UID_MAX);
    }

    return EST_AUTH_HDR_GOOD;
}

void mg_send_authorization_request (struct mg_connection *conn)
{
    conn->status_code = 401;
    switch (conn->ctx->est_ctx->auth_mode) {
    case AUTH_BASIC:
	mg_printf(conn,
              "%s\r\n"
              "%s: 0\r\n"
              "%s: Basic realm=\"%s\"\r\n\r\n",
	      EST_HTTP_HDR_401,
	      EST_HTTP_HDR_CL,
	      EST_HTTP_HDR_AUTH,
              conn->ctx->est_ctx->realm);
	break;
    case AUTH_DIGEST:
	mg_printf(conn,
              "%s\r\n"
              "%s: 0\r\n"
              "%s: Digest qop=\"auth\", "
              "realm=\"%s\", nonce=\"%lu\"\r\n\r\n",
	      EST_HTTP_HDR_401,
	      EST_HTTP_HDR_CL,
	      EST_HTTP_HDR_AUTH,
              conn->ctx->est_ctx->realm,
              (unsigned long)time(NULL));
	break;
    case AUTH_TOKEN:
	mg_printf(conn,
              "%s\r\n"
              "%s: 0\r\n"
              "%s: Bearer realm=\"%s\"\r\n\r\n",
	      EST_HTTP_HDR_401,
	      EST_HTTP_HDR_CL,
	      EST_HTTP_HDR_AUTH,
              conn->ctx->est_ctx->realm);
	break;
    case AUTH_FAIL:
    case AUTH_NONE:
    default:
	/* These modes are not valid at this point
	 * nothing to do here. */
	break;
    }
}


// Parse HTTP headers from the given buffer, advance buffer to the point
// where parsing stopped.
static void parse_http_headers (char **buf, struct mg_request_info *ri)
{
    int i;

    for (i = 0; i < (int)ARRAY_SIZE(ri->http_headers); i++) {
        ri->http_headers[i].name = skip_quoted(buf, ":", " ", 0);
        ri->http_headers[i].value = skip(buf, EST_HTTP_HDR_EOL);
        if (ri->http_headers[i].name[0] == '\0') {
            break;
        }
        ri->num_headers = i + 1;
    }
}

static int is_valid_http_method (const char *method)
{
    /* EST only allows GET & POST */
    return !strcmp(method, "GET") || !strncmp(method, "POST", 4);
}

// Parse HTTP request, fill in mg_request_info structure.
// This function modifies the buffer by NUL-terminating
// HTTP request components, header names and header values.
static int parse_http_message (char *buf, int len, struct mg_request_info *ri)
{
    int request_length = get_request_len(buf, len);

    if (request_length > 0) {
        // Reset attributes. DO NOT TOUCH is_ssl, remote_ip, remote_port
        ri->remote_user = ri->request_method = ri->uri = ri->http_version = NULL;
        ri->num_headers = 0;

        buf[request_length - 1] = '\0';

        // RFC says that all initial whitespaces should be ignored
        while (*buf != '\0' && isspace(*(unsigned char*)buf)) {
            buf++;
        }
        ri->request_method = skip(&buf, " ");
        ri->uri = skip(&buf, " ");
        ri->http_version = skip(&buf, EST_HTTP_HDR_EOL);
        parse_http_headers(&buf, ri);
    }
    EST_LOG_INFO("request_len=%d", request_length);
    return request_length;
}

static int parse_http_request (char *buf, int len, struct mg_request_info *ri)
{
    int result = parse_http_message(buf, len, ri);

    if (result > 0 &&
        is_valid_http_method(ri->request_method) &&
        !strncmp(ri->http_version, "HTTP/", 5)) {
        ri->http_version += 5; // Skip "HTTP/"
    } else {
        result = -1;
    }
    return result;
}

// Keep reading the input (either opened file descriptor fd, or socket sock,
// or SSL descriptor ssl) into buffer buf, until \r\n\r\n appears in the
// buffer (which marks the end of HTTP request). Buffer buf may already
// have some data. The length of the data is stored in nread.
// Upon every read operation, increase nread by the number of bytes read.
// Return negative value -EST_ERR... on error, or number of bytes read on success.
static int read_request (FILE *fp, struct mg_connection *conn,
                         char *buf, int bufsiz, int *nread)
{
    int request_len, n = 1;

    request_len = get_request_len(buf, *nread);
    while (*nread < bufsiz && request_len == 0 && n >= 0) {
        n = pull(fp, conn, buf + *nread, bufsiz - *nread);
        if (n > 0) {
            *nread += n;
            request_len = get_request_len(buf, *nread);
        }
    }

    if (n <= 0) { // No more data to read or
        // recv() error -> propagate error; do not process a b0rked-with-very-high-probability request
        return n;
    }
    return request_len < 0 ? -EST_ERR_SSL_READ : request_len;
}

#define EST_MAX_CONTENT_LEN 8192
/*
 * This function is called by the Mongoose code when an
 * incoming HTTP request is processed.
 * Returns 0 on success, non-zero if the request wasn't
 * handled.
 */
static int est_mg_handler (struct mg_connection *conn)
{
    const struct mg_request_info *request_info = mg_get_request_info(conn);
    EST_CTX *ectx = conn->ctx->est_ctx;
    char *body;
    int cl;
    int est_rv = EST_ERR_NONE;
    const char *cl_hdr; /* content length html header */
    const char *ct_hdr; /* content type html header */

    cl_hdr = mg_get_header(conn, "Content-Length");
    if (cl_hdr) {
        cl = atoi(cl_hdr);
	/*
	 * Let's be defensive about the incoming content
	 * length header from the client.
	 */
	if (cl > EST_MAX_CONTENT_LEN) {
	    EST_LOG_WARN("HTTP request content length greater than %d", 
		         EST_MAX_CONTENT_LEN);
	    return (EST_ERR_BAD_CONTENT_LEN);
	}
        body = (char *)malloc(cl+1);
        mg_read(conn, body, cl);
	/* Make sure the buffer is null terminated */
	body[cl] = 0x0;
    } else {
        cl = 0;
        body = NULL;
    }
    ct_hdr = mg_get_header(conn, "Content-Type");
    if (ectx->est_mode == EST_SERVER) {
        est_rv = est_http_request(ectx, conn,
                                  (char*)request_info->request_method,
                                  (char*)request_info->uri, body, cl, ct_hdr);
    } else if (ectx->est_mode == EST_PROXY) {
        est_rv = est_proxy_http_request(ectx, conn,
                                        (char*)request_info->request_method,
                                        (char*)request_info->uri, body, cl, ct_hdr);
    }
#if 0
    if (est_rv != EST_ERR_NONE) {
        EST_LOG_ERR("EST error response code: %d (%s)", 
		    est_rv, EST_ERR_NUM_TO_STR(est_rv));
    }
#endif
    if (cl_hdr) {
        free(body);
    }
    return est_rv;
}


// This is the heart of the Mongoose's logic.
// This function is called when the request is read, parsed and validated,
// and Mongoose must decide what action to take: serve a file, or
// a directory, or call embedded function, etcetera.
static void handle_request (struct mg_connection *conn)
{
    struct mg_request_info *ri = &conn->request_info;
    int uri_len;
    int rv;

    if ((conn->request_info.query_string = strchr(ri->uri, '?')) != NULL) {
        *((char*)conn->request_info.query_string++) = '\0';
    }
    uri_len = (int)strnlen(ri->uri, EST_URI_MAX_LEN);
    url_decode(ri->uri, uri_len, (char*)ri->uri, uri_len + 1, 0);
    remove_double_dots_and_double_slashes((char*)ri->uri);

    // EST_LOG_INFO("Request URI: %s", ri->uri);
    /*
     * Process the request
     */
    rv = est_mg_handler(conn);
    if (EST_ERR_NONE != rv) {
	EST_LOG_WARN("Incoming request failed rv=%d (%s)", 
		     rv, EST_ERR_NUM_TO_STR(rv));
    }
}

static void log_header (const struct mg_connection *conn, const char *header)
{
    const char *header_value = mg_get_header(conn, header);
    EST_LOG_INFO("%s: %s", header, header_value ? header_value : "(none)");
}

static void log_access (const struct mg_connection *conn)
{
    const struct mg_request_info *ri;
    char date[64], src_addr[20];


    strftime(date, sizeof(date), "%Y-%b-%d %H:%M:%S %z",
             localtime(&conn->birth_time));

    ri = &conn->request_info;

    sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
    EST_LOG_INFO("%s - %s [%s] \"%s %s HTTP/%s\" %d %" INT64_FMT,
                 src_addr, ri->remote_user == NULL ? "-" : ri->remote_user, date,
                 ri->request_method ? ri->request_method : "-",
                 ri->uri ? ri->uri : "-", ri->http_version,
                 conn->status_code, conn->num_bytes_sent);
//  log_header(conn, "Referer");
    log_header(conn, "User-Agent");
}

// Return OpenSSL error message
static const char *ssl_error (void)
{
    unsigned long err;

    err = ERR_get_error();
    return err == 0 ? "" : ERR_error_string(err, NULL);
}

// Dynamically load SSL library. Set up ctx->ssl_ctx pointer.
static int set_ssl_option (struct mg_context *ctx)
{
    struct mg_connection *conn;
    EST_CTX *ectx;
    SSL_CTX *ssl_ctx;
    EC_KEY *ecdh = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    char sic[12] = "EST";

    if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        cry(fc(ctx), "SSL_CTX_new (server) error: %s", ssl_error());
        return 0;
    }
    ctx->ssl_ctx = ssl_ctx;
    ectx = ctx->est_ctx;

    conn = fc(ctx);
    conn->request_info.ev_data = ctx->ssl_ctx;


    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    /*
     * Set the Session ID context to enable OpenSSL session
     * reuse, which improves performance.  We set the ID to
     * ESTxxxxxxxx, where the x values are random numbers
     */
    if (!RAND_bytes((unsigned char*)&sic[3], 8)) {
	EST_LOG_WARN("RNG failure while setting SIC: %s", ssl_error());
    }
    SSL_CTX_set_session_id_context(ssl_ctx, (const unsigned char*)&sic, 11);

    // load in the CA cert(s) used to verify client certificates
    SSL_CTX_set_cert_store(ssl_ctx, ectx->trusted_certs_store);
    //The ssl code will free this store from ssl_ctx later
    ectx->trusted_certs_store = NULL;  

    /*
     * Note that we disable TLS tickets, which is another
     * way to reuse TLS sessions to avoid all the key exchange
     * overhead of the TLS handshake.  We've enabled session
     * reuse above.  But session reuse will not 
     * work when ticket support is enabled on the server.
     * We may want to look into enabling tickets
     * in the future, but for now the session reuse
     * above gives us a performance boost.
     *
     * The other options set here are to improve forward
     * secrecy and comply with the EST draft.
     */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 |
                        SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_TLSv1 |
                        SSL_OP_SINGLE_ECDH_USE | 
			SSL_OP_NO_TICKET);

    /* 
     * Set the ECDH single use parms.  Use the configured
     * curve, or use prime256v1 as the default.
     */
    if (ectx->ecdhe_nid) {
	/* Setup the user selected curve */
	ecdh = EC_KEY_new_by_curve_name(ectx->ecdhe_nid);
	EST_LOG_INFO("Using non-default ECDHE curve (nid=%d)", ectx->ecdhe_nid);
    } else {
	/* Default to prime256 curve */
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	EST_LOG_INFO("Using default ECDHE curve (prime256v1)");
    }
    if (ecdh == NULL) {
        EST_LOG_ERR("Failed to generate temp ecdh parameters");
        return 0;
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    /*
     * Setup additional cert checks including CRL, depth
     * and purpose.
     */
    vpm = X509_VERIFY_PARAM_new();
    /* Enable CRL checks */
    if (ectx->enable_crl) {
	X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK |
                                    X509_V_FLAG_CRL_CHECK_ALL);
    }
    X509_VERIFY_PARAM_set_depth(vpm, EST_TLS_VERIFY_DEPTH);
    /* Note: the purpose is only checked when the keyusage
     * value is present in the client's cert */
    X509_VERIFY_PARAM_set_purpose(vpm, X509_PURPOSE_SSL_CLIENT);
    SSL_CTX_set1_param(ssl_ctx, vpm);
    X509_VERIFY_PARAM_free(vpm);

    /*
     * Set the single-use DH parameters if the application
     * has requested this capability.
     */
    if (ectx->dh_tmp) {
	SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ssl_ctx, ectx->dh_tmp);
	DH_free(ectx->dh_tmp);
	ectx->dh_tmp = NULL;
    }

    if (ectx->enable_srp) {
	EST_LOG_INFO("Enabling TLS SRP mode");
	if (!SSL_CTX_set_cipher_list(ssl_ctx, EST_CIPHER_LIST_SRP_SERVER)) { 
	    EST_LOG_ERR("Failed to set SSL cipher suites");
	    return 0;
	}
	/*
	 * Set the application specific handler for
	 * providing the SRP parameters during user 
	 * authentication.
	 */
	SSL_CTX_set_srp_username_callback(ssl_ctx, ectx->est_srp_username_cb);
    } else {
	EST_LOG_INFO("TLS SRP not enabled");
	/*
	 * Set the TLS cipher suites that should be allowed.
	 * This disables anonymous and null ciphers
	 */
	if (!SSL_CTX_set_cipher_list(ssl_ctx, EST_CIPHER_LIST)) { 
	    EST_LOG_ERR("Failed to set SSL cipher suites");
	    return 0;
	}
    }

    if (SSL_CTX_use_certificate(ssl_ctx, ectx->server_cert) == 0) {
	EST_LOG_ERR("Unable to set server certificate");
        return 0;
    }
    if (SSL_CTX_use_PrivateKey(ssl_ctx, ectx->server_priv_key) == 0) {
	EST_LOG_ERR("Unable to set server private key");
        return 0;
    }

    /*
     * There should be no need to include the cert chain for the
     * server's certificate in the TLS Certificate message from
     * the server.  The reason is the EST draft specifies that
     * all the subordinate CA certs should be included in the
     * cacerts message flow.  Hence, the client will already have
     * the full cert chain.  Therfore, the TLS handshake will only
     * contain the server's cert, not the full chain. 
     *
      SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx,
                                         ctx->est_ctx->http_cert_file);
     */

    return 1;
}

static void reset_per_request_attributes (struct mg_connection *conn)
{
    conn->path_info = (char *)(conn->request_info.ev_data = NULL);
    conn->num_bytes_sent = conn->consumed_content = 0;
    conn->status_code = -1;
    conn->must_close = conn->request_len = 0;
}

static int is_valid_uri (const char *uri)
{
    // Conform to http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
    // URI can be an asterisk (*) or should start with slash.
    return uri[0] == '/' || (uri[0] == '*' && uri[1] == '\0');
}

static EST_ERROR process_new_connection (struct mg_connection *conn)
{
    EST_ERROR rv = EST_ERR_NONE;
    struct mg_request_info *ri = &conn->request_info;
    int keep_alive_enabled, keep_alive, discard_len;
    const char *cl;

    keep_alive_enabled = conn->ctx->enable_keepalives;
    keep_alive = 0;

    // Important: on new connection, reset the receiving buffer. Credit goes to crule42.
    conn->data_len = 0;
    do {
        EST_LOG_INFO("Processing HTTP request...");
        reset_per_request_attributes(conn);
        conn->request_len = read_request(NULL, conn, conn->buf, conn->buf_size,
                                         &conn->data_len);
	if (conn->request_len < 0) {
	    rv = (EST_ERROR)-conn->request_len;
	    // EST_LOG_ERR("Processing HTTP request, error=%d (%s)", rv, EST_ERR_NUM_TO_STR(rv));
	} else {
	    // EST_LOG_INFO("Processing HTTP request, length=%d", conn->request_len);
	}
        assert(conn->request_len < 0 || conn->data_len >= conn->request_len);
        if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
            send_http_error(conn, 413, "Request Too Large", "%s", "");
            return EST_ERR_BAD_CONTENT_LEN;
        }
        if (conn->request_len <= 0) {
	    if (conn->request_len < 0) {
		// An error occurred as given in rv. There should be more info in the log regarding ERRNO or SSL_ERROR
		return rv;
	    } // else client closed the connection
	    return EST_ERR_SOCKET_STOP; 
        }
        if (parse_http_request(conn->buf, conn->buf_size, ri) <= 0 ||
            !is_valid_uri(ri->uri)) {
            // Do not put garbage in the access log, just send it back to the client
            send_http_error(conn, 400, "Bad Request",
                            "Cannot parse HTTP request: [%.*s]", conn->data_len, conn->buf);
            conn->must_close = 1;
        } else if (strcmp(ri->http_version, "1.0") &&
                   strcmp(ri->http_version, "1.1")) {
            log_access(conn);
            // Request seems valid, but HTTP version is strange
            send_http_error(conn, 505, "HTTP version not supported", "%s", "");
        } else {
            // Request is valid, handle it
            log_access(conn);
            if ((cl = get_header(ri, "Content-Length")) != NULL) {
                conn->content_len = strtoll(cl, NULL, 10);
            } else if (!mg_strcasecmp(ri->request_method, "POST") ||
                       !mg_strcasecmp(ri->request_method, "PUT")) {
                conn->content_len = -1;
            } else {
                conn->content_len = 0;
            }
            conn->birth_time = time(NULL);
            handle_request(conn);
        }
        if (ri->remote_user != NULL) {
            free((void*)ri->remote_user);
        }

        // NOTE(lsm): order is important here. should_keep_alive() call
        // is using parsed request, which will be invalid after memmove's below.
        // Therefore, memorize should_keep_alive() result now for later use
        // in loop exit condition.
        keep_alive = should_keep_alive(conn);

        // Discard all buffered data for this request
        discard_len = conn->content_len >= 0 &&
                      conn->request_len + conn->content_len < (int64_t)conn->data_len ?
                      (int)(conn->request_len + conn->content_len) : conn->data_len;
	if ((conn->data_len - discard_len) > 0) {
	    memmove(conn->buf, conn->buf + discard_len, conn->data_len - discard_len);
	}
        conn->data_len -= discard_len;
        assert(conn->data_len >= 0);
        assert(conn->data_len <= conn->buf_size);

	keep_alive = (keep_alive_enabled && keep_alive && 
		      conn->ctx->stop_flag == 0 && conn->content_len >= 0);
	if (keep_alive && conn->data_len <= 0) {
	    EST_LOG_INFO("Awaiting any further request on socket %d...\n", conn->client.sock);
	}

    } while (keep_alive);
    return rv;
}


/*! @brief est_server_handle_request() is used by an application 
    to process and EST request.  The application is responsible
    for opening a listener socket.  When an EST request comes in
    on the socket, the application uses this function to hand-off
    the request to libest.

    @param ctx Pointer to the EST_CTX, which was provided
               when est_server_init()  or est_proxy_init() was invoked.
    @param fd File descriptor that will be read to retrieve the
              HTTP request from the client.  This is typically
	      a TCP socket file descriptor.

    est_server_handle_request() is used by an application 
    when an incoming EST request needs to be processed.  This request
    would be a cacerts, simpleenroll, reenroll, or csrattrs request. 
    This is used when implementing an EST server.  The application 
    is responsible for opening and listening to a TCP socket for
    incoming EST requests.  When data is ready to be read from
    the socket, this API entry point should be used to allow libest 
    to read the request from the socket and respond to the request.
 

    @return EST_ERROR.
*/
EST_ERROR est_server_handle_request (EST_CTX *ctx, int fd)
{
    struct mg_connection *conn;
    struct socket accepted;
    socklen_t len;
    char ipstr[INET6_ADDRSTRLEN];
    int port;
    struct sockaddr_storage addr;
    int ssl_err, err_code;
    EST_ERROR rv = EST_ERR_NONE;

    if (!ctx) {
        EST_LOG_ERR("Null EST context");
        return (EST_ERR_NO_CTX);
    }
    if (!ctx->mg_ctx) {
        EST_LOG_ERR("Null EST MG context");
        return (EST_ERR_NO_CTX);
    }

    accepted.sock = fd;

    len = sizeof(struct sockaddr_storage);
    if (getpeername(fd, (struct sockaddr*)&addr, &len) < 0) {
	EST_LOG_ERR("getpeername() failed");
	/* This should never happen, not sure what would cause this */
	return (EST_ERR_SYSCALL);
    }
    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        memcpy(&accepted.rsa.sin, &addr, sizeof(struct sockaddr_in));
        port = ntohs(accepted.rsa.sin.sin_port);
        inet_ntop(AF_INET, &accepted.rsa.sin.sin_addr, ipstr, sizeof ipstr);
    } else { // AF_INET6
        memcpy(&accepted.rsa.sin6, &addr, sizeof(struct sockaddr_in6));
        port = ntohs(accepted.rsa.sin6.sin6_port);
        inet_ntop(AF_INET6, &accepted.rsa.sin6.sin6_addr, ipstr, sizeof ipstr);
    }
    EST_LOG_INFO("Peer IP address and port: %s:%d", ipstr, port);

    conn = (struct mg_connection*)calloc(1, sizeof(*conn) + MAX_REQUEST_SIZE);
    if (conn == NULL) {
        cry(fc(ctx->mg_ctx), "%s", "Cannot create new connection struct, OOM");
	return (EST_ERR_MALLOC);
    } else {
        conn->buf_size = MAX_REQUEST_SIZE;
        conn->buf = (char*)(conn + 1);

        conn->client = accepted;
        conn->birth_time = time(NULL);
        conn->ctx = ctx->mg_ctx;

        // Fill in IP, port info early so even if SSL setup below fails,
        // error handler would have the corresponding info.
        conn->request_info.remote_port = ntohs(conn->client.rsa.sin.sin_port);
        memcpy(&conn->request_info.remote_ip, &conn->client.rsa.sin.sin_addr.s_addr, 4);
        conn->request_info.remote_ip = ntohl(conn->request_info.remote_ip);
        conn->request_info.is_ssl = 1;

        /*
         * EST require TLS,  Setup the TLS tunnel
         */
        conn->ssl = SSL_new(conn->ctx->ssl_ctx);
        if (conn->ssl == NULL) {
            EST_LOG_ERR("Error creating TLS context");
        } else {
            SSL_set_fd(conn->ssl, conn->client.sock);
            ssl_err = SSL_accept(conn->ssl); 
	    err_code = SSL_get_error(conn->ssl, ssl_err);
	    if (ssl_err <= 0 && (err_code != SSL_ERROR_NONE && 
				 err_code != SSL_ERROR_WANT_READ && err_code != SSL_ERROR_WANT_WRITE)) {
		EST_LOG_ERR("SSL_accept error: %d (%s)", err_code, ossl_error_string(err_code));
		switch (err_code) {
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_SSL:
		    rv = general_ssl_error(conn, ssl_err);
		    break;
		case SSL_ERROR_WANT_X509_LOOKUP:
		    ossl_dump_ssl_errors();
		    rv = EST_ERR_AUTH_FAIL;
		    break;
		default:
		    ossl_dump_ssl_errors();
		    rv = EST_ERR_SYSCALL;
		    break;
		}
	    } else { // this includes SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE
		rv = process_new_connection(conn);
	    }
            ssl_err = SSL_shutdown(conn->ssl);
	    switch (ssl_err) {
	    case 0:
		/* OpenSSL docs say to call shutdown again for this case */
		SSL_shutdown(conn->ssl);
		EST_LOG_INFO("SSL_shutdown performed in two phases");
		break;
	    case 1:
		/* Nothing to do, shutdown worked */
		EST_LOG_INFO("SSL_shutdown succeeded");
		break;
	    default:
		/* Log an error */
		EST_LOG_WARN("SSL_shutdown failed\n");
		break;
	    }
            SSL_free(conn->ssl);
            conn->ssl = NULL;
        }
        free(conn);
    }
    return (rv);
}


static void free_context (struct mg_context *ctx)
{
    // Deallocate SSL context
    if (ctx->ssl_ctx != NULL) {
        SSL_CTX_free(ctx->ssl_ctx);
    }

    // Deallocate context itself
    free(ctx);
}

void mg_stop (struct mg_context *ctx)
{
    ctx->stop_flag = 1;

    free_context(ctx);
}

struct mg_context *mg_start (void *user_data)
{
    struct mg_context *ctx;

    /*
     * Prevent SIGPIPE interrupt when writing to
     * a closed socket.  This is a defensive measure
     * in case a client sends us a bogus request that
     * results in a socket closure.  
     */
#ifndef _MSC_VER // Otherwise, we get a runtime assertion failure in winsig.c
    signal(SIGPIPE, SIG_IGN);
#endif

    // Allocate context and initialize reasonable general case defaults.
    // TODO(lsm): do proper error handling here.
    if ((ctx = (struct mg_context*)calloc(1, sizeof(*ctx))) == NULL) {
        return NULL;
    }
    ctx->user_data = user_data;
    ctx->est_ctx = (EST_CTX*)user_data;
    ctx->enable_keepalives = 1; 
    if (!set_ssl_option(ctx)) {
        free_context(ctx);
        return NULL;
    }

    return ctx;
}

EST_ERROR est_send_csrattr_data (EST_CTX *ctx, char *csr_data, int csr_len, void *http_ctx)
{
    char http_hdr[EST_HTTP_HDR_MAX];
    int hdrlen;
    struct mg_connection *conn = (struct mg_connection*)http_ctx;

    if ((csr_len > 0) && csr_data) {
        /*
         * Send HTTP 200 header
         */
        snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200, EST_HTTP_HDR_EOL,
                 EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
        hdrlen = strnlen(http_hdr, EST_HTTP_HDR_MAX);
        snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
                 EST_HTTP_CT_CSRATTRS, EST_HTTP_HDR_EOL);
        hdrlen = strnlen(http_hdr, EST_HTTP_HDR_MAX);
        snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CE,
                 EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL);
        hdrlen = strnlen(http_hdr, EST_HTTP_HDR_MAX);
        snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %d%s%s", EST_HTTP_HDR_CL,
                 csr_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
        if (!mg_write(conn, http_hdr, strnlen(http_hdr, EST_HTTP_HDR_MAX))) {
            free(csr_data);
            return (EST_ERR_HTTP_WRITE);
        }

        /*
         * Send the CSR in the body
         */
        if (!mg_write(conn, csr_data, csr_len)) {
            free(csr_data);
            return (EST_ERR_HTTP_WRITE);
        }
        free(csr_data);
    } else {
	if (csr_data) {
            free(csr_data);
	}
        /* Send a 204 response indicating the server doesn't have a CSR */
	est_send_http_error(ctx, http_ctx, EST_ERR_HTTP_NO_CONTENT);
    }
    return (EST_ERR_NONE);
}
