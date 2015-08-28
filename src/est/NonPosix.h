/*------------------------------------------------------------------
 * est/NonPosix.h - POSIX compensation layer for, e.g., Windows and QNX
 * Copyright (c) 2014 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

#ifndef NonPosix_H
#define NonPosix_H

//http://stackoverflow.com/questions/6365058/alternative-unistd-h-header-file-for-visual-studio-2010
#if !defined _MSC_VER || _MSC_VER < 1700
#include <unistd.h>
#else
#include <io.h>
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined (QNX650_)

// Visual Studio 6 does not know __func__ or __FUNCTION__
// The rest of MS compilers use __FUNCTION__, not C99 __func__
#ifdef _MSC_VER

#if _MSC_VER < 1300
#define STRX(x) # x
#define STR(x) STRX(x)
#define __func__ "line " STR(__LINE__)
#else
#define __func__  __FUNCTION__
#endif

#define HAVE_STRNLEN
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#endif // _MSC_VER

// DvO: QNX 6.5 and MinGW need definitions, taken from http://unixpapa.com/incnote/string.html
#include <string.h>
char *strndup(const char *str, size_t len);
#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen);
#endif

#ifdef _WIN32
#undef  INT64_MAX
#define HAVE_STDINT 1
#endif

#ifdef HAVE_STDINT
#include <stdint.h>
#else
typedef unsigned char uint8_t;
#endif

#ifdef _WIN32

#ifdef _MSC_VER
#define strtoull(x, y, z) strtoul(x, y, z)
#define strtoll(x, y, z) strtol(x, y, z)
#define atoll(str)	strtoull(str, 0, 10)
int strncasecmp (const char *s1, const char *s2, size_t n);
#define strcasecmp(x,y) strncasecmp(x,y,-1)
#define PRId64 "lld" // inttypes.h
#define usleep(x) Sleep(x)
//https://social.msdn.microsoft.com/Forums/vstudio/en-US/6673106b-f15f-4ee0-aac5-1199ed26d1a2/debug-assertion-failed?forum=vcgeneral&prof=required
//#define close(x) _close(x) // On attempt to close(), we get a runtime assertion failure on close.c
#define close(x) closesocket(x)
#define write(x, y, z) _write((x), (y), (unsigned)z)
#define read(x, y, z) _read((x), (y), (unsigned)z)
#define fileno(x) _fileno(x)
#include <process.h>
#define getpid() _getpid()
#else
#define AI_ADDRCONFIG 0x0000 // dummy for missing definition from netdb.h
#endif // defined _MSC_VER

#ifndef DISABLE_TSEARCH
void tdestroy (void *root, void (*freenode) (void *));
#ifdef _MSC_VER
void *tsearch(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *));

void *tfind(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *));

void *tdelete(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *));
#endif // _MSC_VER
#endif // DISABLE_TSEARCH


/* compensating for
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
*/

#if defined(_MSC_VER) || defined(__MINGW32__)
// for inclusion of getaddrinfo, inet_ntop etc.
// Force Vista
#undef  WINVER
#define WINVER 0x0600
#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0600
//define _WIN32_WINNT 0x0501 // XP
#include <Ws2tcpip.h> // this includes winsock2.h, preventing inclusion of incompatible winsock.h
#endif

#if 0 // defined(_MSC_VER) // (NTDDI_VERSION >= NTDDI_VISTA)
WINSOCK_API_LINKAGE 
INT WSAAPI inet_pton(
    __in                                INT             Family,
    __in                                PCSTR           pszAddrString,
    __out_bcount(sizeof(IN6_ADDR))      PVOID           pAddrBuf
    );
PCSTR WSAAPI inet_ntop(
    __in                                INT             Family,
    __in                                PVOID           pAddr,
    __out_ecount(StringBufSize)         PSTR            pStringBuf,
    __in                                size_t          StringBufSize
    );
#endif

#if defined(__MINGW32__)
//http://sourceforge.net/p/mingw/bugs/1641/
int inet_pton(int af, const char *src, void *dst);

//http://sourceforge.net/p/mingw/bugs/2147/
const char* inet_ntop(int af, const void *src, char *dst, DWORD size);
#endif

int memset_s(void *, int, size_t);
char* strtok_r(char *str, const char *delim, char **nextp);

#define sleep(x) Sleep((x) * 1000)
//#define flockfile(x) EnterCriticalSection(&global_log_file_lock)
#define flockfile(filehandle)
//#define funlockfile(x) LeaveCriticalSection(&global_log_file_lock)
#define funlockfile(filehandle)

#define SIGPIPE NSIG // dummy

#ifdef _MSC_VER
#define no_argument        0
#define required_argument  1
#define optional_argument  2
struct option {
	/* name of long option */
	const char *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	int has_arg;
	/* if not NULL, set *flag to val when option found */
	int *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	int val;
};
int getopt(int nargc, char * const *nargv, const char *options);
int getopt_long(int nargc, char * const *nargv, const char *options, const struct option *long_options, int *idx);
#else
#include "getopt.h"
#endif

#define REPLACE_GETOPT 1
extern int	opterr;
extern int	optind;
extern int	optopt;
extern int	optreset;
extern char    *optarg;

#ifndef _MSC_VER
DWORD WINAPI GetCurrentThreadId(void);
#endif

#endif

#else // #not: defined(_MSC_VER) || defined(__MINGW32__) || defined (QNX650_)

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>

#endif

#endif // NonPosix_H
