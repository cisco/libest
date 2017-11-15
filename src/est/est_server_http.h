/*------------------------------------------------------------------
 * est/est_server_http.h - EST HTTP server
 *
 *			   This code is adapted from the Mongoose
 *			   HTTP server, which is licensed under the
 *			   MIT license.  The Mongoose copyright
 *			   is retained below.
 *
 * May, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
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

#ifndef MONGOOSE_HEADER_INCLUDED
#define  MONGOOSE_HEADER_INCLUDED

#include <stdio.h>
#include <stddef.h>
#include "est_locl.h"
#if defined(_WIN32) && !defined(__SYMBIAN32__)

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif

#ifndef _WIN32_WCE
#include <process.h>
#include <direct.h>
#include <io.h>
#else // _WIN32_WCE

typedef long off_t;

#define errno   GetLastError()
#define strerror(x)  _ultoa(x, (char*)_alloca(sizeof(x) * 3 ), 10)
#endif // _WIN32_WCE

#define MAKEUQUAD(lo, hi) ((uint64_t)(((uint32_t)(lo)) | \
                                      ((uint64_t)((uint32_t)(hi))) << 32))
#define RATE_DIFF 10000000 // 100 nsecs
#define EPOCH_DIFF MAKEUQUAD(0xd53e8000, 0x019db1de)
#define SYS2UNIX_TIME(lo, hi) \
    (time_t)((MAKEUQUAD((lo), (hi)) - EPOCH_DIFF) / RATE_DIFF)

// Visual Studio 6 does not know __func__ or __FUNCTION__
// The rest of MS compilers use __FUNCTION__, not C99 __func__
// Also use _strtoui64 on modern M$ compilers
#if defined(_MSC_VER) && _MSC_VER < 1300
#define STRX(x) # x
#define STR(x) STRX(x)
#define __func__ "line " STR(__LINE__)
#define strtoull(x, y, z) strtoul(x, y, z)
#define strtoll(x, y, z) strtol(x, y, z)
#else
#define __func__  __FUNCTION__
#define strtoull(x, y, z) _strtoui64(x, y, z)
#define strtoll(x, y, z) _strtoi64(x, y, z)
#endif // _MSC_VER

#define ERRNO   GetLastError()
#define NO_SOCKLEN_T
#define SSL_LIB   "ssleay32.dll"
#define CRYPTO_LIB  "libeay32.dll"
#define O_NONBLOCK  0
#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK  WSAEWOULDBLOCK
#endif // !EWOULDBLOCK
#define _POSIX_
#define INT64_FMT  "I64d"

#define WINCDECL __cdecl
#define SHUT_WR 1
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define mg_sleep(x) Sleep(x)

#define pipe(x) _pipe(x, MG_BUF_LEN, _O_BINARY)
#define popen(x, y) _popen(x, y)
#define pclose(x) _pclose(x)
#define close(x) _close(x)
#define dlsym(x, y) GetProcAddress((HINSTANCE)(x), (y))
#define RTLD_LAZY  0
#define fseeko(x, y, z) _lseeki64(_fileno(x), (y), (z))
#define fdopen(x, y) _fdopen((x), (y))
#define write(x, y, z) _write((x), (y), (unsigned)z)
#define read(x, y, z) _read((x), (y), (unsigned)z)
#define flockfile(x) EnterCriticalSection(&global_log_file_lock)
#define funlockfile(x) LeaveCriticalSection(&global_log_file_lock)
#define sleep(x) Sleep((x) * 1000)

#if !defined(fileno)
#define fileno(x) _fileno(x)
#endif // !fileno MINGW #defines fileno

typedef HANDLE pthread_mutex_t;
typedef struct { HANDLE signal, broadcast; } pthread_cond_t;
typedef DWORD pthread_t;
#define pid_t HANDLE // MINGW typedefs pid_t to int. Using #define here.

static int pthread_mutex_lock(pthread_mutex_t *);
static int pthread_mutex_unlock(pthread_mutex_t *);

static void to_unicode(const char *path, wchar_t *wbuf, size_t wbuf_len);

struct file;

#if defined(HAVE_STDINT)
#include <stdint.h>
#else
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
#define INT64_MAX  9223372036854775807
#endif // HAVE_STDINT

// POSIX dirent interface
struct dirent {
    char d_name[PATH_MAX];
};

typedef struct DIR {
    HANDLE handle;
    WIN32_FIND_DATAW info;
    struct dirent result;
} DIR;

// Mark required libraries
#pragma comment(lib, "Ws2_32.lib")

#else    // UNIX  specific
#ifdef IS_FREEBSD
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#if defined(__MACH__)
#define SSL_LIB   "libssl.dylib"
#define CRYPTO_LIB  "libcrypto.dylib"
#else
#if !defined(SSL_LIB)
#define SSL_LIB   "libssl.so"
#endif
#if !defined(CRYPTO_LIB)
#define CRYPTO_LIB  "libcrypto.so"
#endif
#endif
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
#define mg_mkdir(x, y) mkdir(x, y)
#define mg_remove(x) remove(x)
#define mg_rename(x, y) rename(x, y)
#define mg_sleep(x) usleep((x) * 1000)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;
#define WINCDECL

#endif // End of Windows and UNIX specific includes

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define MG_UID_MAX 256
#define USE_IPV6

#ifndef WIN32
#define POLL poll
#define EST_UINT uint
#else
#define POLL WSAPoll
#define EST_UINT UINT
#endif 

// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
union usa {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if defined(USE_IPV6)
    struct sockaddr_in6 sin6;
#endif
};

// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
    struct socket *next; // Linkage
    SOCKET sock;         // Listening socket
    union usa lsa;       // Local socket address
    union usa rsa;       // Remote socket address
    int is_ssl;          // Is socket SSL-ed
};

// Handle for the HTTP service itself
struct mg_context {
    volatile int stop_flag;      // Should we stop event loop
    SSL_CTX *ssl_ctx;            // SSL context
    void *user_data;             // User-defined data
    EST_CTX *est_ctx;
    int enable_keepalives;
};

// This structure contains information about the HTTP request.
struct mg_request_info {
    const char *request_method; // "GET", "POST", etc
    const char *uri;            // URL-decoded URI
    const char *http_version;   // E.g. "1.0", "1.1"
    const char *query_string;   // URL part after '?', not including '?', or NULL
    long remote_ip;             // Client's IP address
    int remote_port;            // Client's port
    int is_ssl;                 // 1 if SSL-ed, 0 if not
    int num_headers;            // Number of headers
    struct mg_header {
        const char *name;       // HTTP header name
        const char *value;      // HTTP header value
    } http_headers[64];         // Maximum 64 headers
    void *user_data;            // User data pointer passed to the mg_start()
    void *ev_data;              // Event-specific data pointer
};

// Handle for the individual connection
struct mg_connection {
    struct mg_request_info request_info;
    struct mg_context *ctx;
    int read_timeout;
    SSL *ssl;                    // SSL descriptor
    struct socket client;        // Connected client
    time_t birth_time;           // Time when request was received
    int64_t num_bytes_sent;      // Total bytes sent to client
    int64_t content_len;         // Content-Length header value
    int64_t consumed_content;    // How many bytes of content have been read
    char *buf;                   // Buffer for received data
    char *path_info;             // PATH_INFO part of the URL
    int must_close;              // 1 if connection must be closed
    int buf_size;                // Buffer size
    int request_len;             // Size of the request + headers in a buffer
    int data_len;                // Total size of data in a buffer
    int status_code;             // HTTP reply status code, e.g. 200
    char user_id[MG_UID_MAX];    // User ID from HTTP auth header
};


// Various events on which user-defined callback function is called by Mongoose.
enum mg_event {
    // New HTTP request has arrived from the client.
    // If callback returns non-NULL, Mongoose stops handling current request.
    // ev_data contains NULL.
    MG_NEW_REQUEST,

    // Mongoose has finished handling the request.
    // Callback return value is ignored.
    // ev_data contains NULL.
    MG_REQUEST_COMPLETE,

    // HTTP error must be returned to the client.
    // If callback returns non-NULL, Mongoose stops handling error.
    // ev_data contains HTTP error code:
    //  int http_reply_status_code = (long) request_info->ev_data;
    MG_HTTP_ERROR,

    // Mongoose logs a message.
    // If callback returns non-NULL, Mongoose stops handling that event.
    // ev_data contains a message to be logged:
    //   const char *log_message = request_info->ev_data;
    MG_EVENT_LOG,

    // SSL initialization, sent before certificate setup.
    // If callback returns non-NULL, Mongoose does not set up certificates.
    // ev_data contains server's OpenSSL context:
    //   SSL_CTX *ssl_context = request_info->ev_data;
    MG_INIT_SSL,

    // Sent on HTTP connect, before websocket handshake.
    // If user callback returns NULL, then mongoose proceeds
    // with handshake, otherwise it closes the connection.
    // ev_data contains NULL.
    MG_WEBSOCKET_CONNECT,

    // Handshake has been successfully completed.
    // Callback's return value is ignored.
    // ev_data contains NULL.
    MG_WEBSOCKET_READY,

    // Incoming message from the client, data could be read with mg_read().
    // If user callback returns non-NULL, mongoose closes the websocket.
    // ev_data contains NULL.
    MG_WEBSOCKET_MESSAGE,

    // Client has closed the connection.
    // Callback's return value is ignored.
    // ev_data contains NULL.
    MG_WEBSOCKET_CLOSE,

    // Mongoose tries to open file.
    // If callback returns non-NULL, Mongoose will not try to open it, but
    // will use the returned value as a pointer to the file data. This allows
    // for example to serve files from memory.
    // ev_data contains file path, including document root path.
    // Upon return, ev_data should return file size,  which should be a long int.
    //
    //   const char *file_name = request_info->ev_data;
    //   if (strcmp(file_name, "foo.txt") == 0) {
    //     request_info->ev_data = (void *) (long) 4;
    //     return "data";
    //   }
    //   return NULL;
    //
    // Note that this even is sent multiple times during one request. Each
    // time mongoose tries to open or stat the file, this event is sent, e.g.
    // for opening .htpasswd file, stat-ting requested file, opening requested
    // file, etc.
    MG_OPEN_FILE,

    // Mongoose initializes Lua server page. Sent only if Lua support is enabled.
    // Callback's return value is ignored.
    // ev_data contains lua_State pointer.
    MG_INIT_LUA,

    // Mongoose has uploaded file to a temporary directory.
    // Callback's return value is ignored.
    // ev_data contains NUL-terminated file name.
    MG_UPLOAD,
};





// Start web server.
//
// Parameters:
//   user_data: user defined data to be associated with the context.
//
// Side-effects: on UNIX, ignores SIGCHLD and SIGPIPE signals. If custom
//    processing is required for these, signal handlers must be set up
//    after calling mg_start().
//
//
// Example:
//   struct mg_context *ctx = mg_start(NULL);
//
// Return:
//   web server context, or NULL on error.
struct mg_context *mg_start(void *user_data);


// Stop the web server.
//
// Must be called last, when an application wants to stop the web server and
// release all associated resources. This function blocks until all Mongoose
// threads are stopped. Context pointer becomes invalid.
void mg_stop(struct mg_context *);


// Add, edit or delete the entry in the passwords file.
//
// This function allows an application to manipulate .htpasswd files on the
// fly by adding, deleting and changing user records. This is one of the
// several ways of implementing authentication on the server side. For another,
// cookie-based way please refer to the examples/chat.c in the source tree.
//
// If password is not NULL, entry is added (or modified if already exists).
// If password is NULL, entry is deleted.
//
// Return:
//   1 on success, 0 on error.
//int mg_modify_passwords_file(const char *passwords_file_name,
//                             const char *domain,
//                             const char *user,
//                             const char *password);


// Return information associated with the request.
struct mg_request_info *mg_get_request_info(struct mg_connection *);


// Send data to the client.
// Return:
//  0   when the connection has been closed
//  -1  on error
//  number of bytes written on success
int mg_write(struct mg_connection *, const void *buf, size_t len);


// Send data to the browser using printf() semantics.
//
// Works exactly like mg_write(), but allows to do message formatting.
// Below are the macros for enabling compiler-specific checks for
// printf-like arguments.

#if 0
#undef PRINTF_FORMAT_STRING
#if _MSC_VER >= 1400
#include <sal.h>
#if _MSC_VER > 1400
#define PRINTF_FORMAT_STRING(s) _Printf_format_string_ s
#else
#define PRINTF_FORMAT_STRING(s) __format_string s
#endif
#else
#define PRINTF_FORMAT_STRING(s) s
#endif

#ifdef __GNUC__
#define PRINTF_ARGS(x, y) __attribute__((format(printf, x, y)))
#else
#define PRINTF_ARGS(x, y)
#endif
#endif

int mg_printf(struct mg_connection *conn, const char *fmt, ...);


// Send contents of the entire file together with HTTP headers.
//void mg_send_file(struct mg_connection *conn, const char *path);


// Read data from the remote end, return number of bytes read.
int mg_read(struct mg_connection *, void *buf, size_t len);


// Get the value of particular HTTP header.
//
// This is a helper function. It traverses request_info->http_headers array,
// and if the header is present in the array, returns its value. If it is
// not present, NULL is returned.
const char *mg_get_header(const struct mg_connection *, const char *name);


// Get a value of particular form variable.
//
// Parameters:
//   data: pointer to form-uri-encoded buffer. This could be either POST data,
//         or request_info.query_string.
//   data_len: length of the encoded data.
//   var_name: variable name to decode from the buffer
//   dst: destination buffer for the decoded variable
//   dst_len: length of the destination buffer
//
// Return:
//   On success, length of the decoded variable.
//   On error:
//      -1 (variable not found).
//      -2 (destination buffer is NULL, zero length or too small to hold the decoded variable).
//
// Destination buffer is guaranteed to be '\0' - terminated if it is not
// NULL or zero length.
//int mg_get_var(const char *data, size_t data_len,
//               const char *var_name, char *dst, size_t dst_len);

// Fetch value of certain cookie variable into the destination buffer.
//
// Destination buffer is guaranteed to be '\0' - terminated. In case of
// failure, dst[0] == '\0'. Note that RFC allows many occurrences of the same
// parameter. This function returns only first occurrence.
//
// Return:
//   On success, value length.
//   On error:
//      -1 (either "Cookie:" header is not present at all or the requested parameter is not found).
//      -2 (destination buffer is NULL, zero length or too small to hold the value).
//int mg_get_cookie(const struct mg_connection *,
//                  const char *cookie_name, char *buf, size_t buf_len);


// Connect to the remote web server.
// Return:
//   On success, valid pointer to the new connection
//   On error, NULL
struct mg_connection *mg_connect(struct mg_context *ctx,
                                 const char *host, int port, int use_ssl);


// Close the connection opened by mg_connect().
void mg_close_connection(struct mg_connection *conn);


// Download given URL to a given file.
//   url: URL to download
//   path: file name where to save the data
//   request_info: pointer to a structure that will hold parsed reply headers
//   buf, bul_len: a buffer for the reply headers
// Return:
//   On error, NULL
//   On success, opened file stream to the downloaded contents. The stream
//   is positioned to the end of the file. It is the user's responsibility
//   to fclose() the opened file stream.
//FILE *mg_fetch(struct mg_context *ctx, const char *url, const char *path,
//               char *buf, size_t buf_len, struct mg_request_info *request_info);


// File upload functionality. Each uploaded file gets saved into a temporary
// file and MG_UPLOAD event is sent.
// Return number of uploaded files.
//int mg_upload(struct mg_connection *conn, const char *destination_dir);


// Convenience function -- create detached thread.
// Return: 0 on success, non-0 on error.
typedef void * (*mg_thread_func_t)(void *);
int mg_start_thread(mg_thread_func_t f, void *p);


// Return builtin mime type for the given file name.
// For unrecognized extensions, "text/plain" is returned.
//const char *mg_get_builtin_mime_type(const char *file_name);


// Return Mongoose version.
const char *mg_version(void);


// Return an error
void mg_send_http_error(struct mg_connection *conn, int status,
                        const char *reason, const char *fmt, ...);

//void mg_handle_cgi_request(struct mg_connection *conn, const char *prog,
//                           int degenerate, // don't sent the POST data to the script and don't parse the return values
//                           char* extra_env, char** return_buf, int* exitstatus);

const void* mg_get_conn_ssl(struct mg_connection *conn);

void mg_send_authorization_request(struct mg_connection *conn);

// Return 1 if request is authorised, 0 otherwise.
// the degenerate flag forces this to occur w/o respsect to the "PROTECT_URI" status of the current URL
// (e.g. this lets the app decide if an authorization check is necessary independent of the URL flags)
// path can be NULL as long as the global password db file is set
// calling this looks for .htaccess at the indicated path
// NOTE: can't mix use of global_passwords_file with this functionality (mongoose always uses global_passwords_file for all URLs)
int mg_check_authorization(struct mg_connection *conn, const char *path, int degenerate);

char *skip(char **buf, const char *delimiters);
char *skip_quoted(char **buf, const char *delimiters,
                  const char *whitespace, char quotechar);
EST_HTTP_AUTH_HDR_RESULT mg_parse_auth_header(struct mg_connection *conn, 
                                              EST_HTTP_AUTH_HDR *ah);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
