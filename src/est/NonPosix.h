/*------------------------------------------------------------------
 * est/NonPosix.h - POSIX compensation layer for, e.g., QNX and MinGW
 * Copyright (c) Siemens AG, 2014
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

#ifndef NonPosix_H
#define NonPosix_H

#if defined(_MSC_VER) || defined(__MINGW32__) || defined (QNX650_)

// Visual Studio 6 does not know __func__ or __FUNCTION__
// The rest of MS compilers use __FUNCTION__, not C99 __func__
#if defined(_MSC_VER) && _MSC_VER < 1300
#define STRX(x) # x
#define STR(x) STRX(x)
#define __func__ "line " STR(__LINE__)
#else
#define __func__  __FUNCTION__
#endif // _MSC_VER

// DvO: QNX 6.5 and MinGW need definitions, taken from http://unixpapa.com/incnote/string.html
#include <string.h>
char *strndup(const char *str, size_t len);
size_t strnlen(const char *s, size_t maxlen);

#define AI_ADDRCONFIG 0x0000 // dummy for missing definition from netdb.h

#include <search.h>

#ifdef __MINGW32__
void tdestroy (void *root, void (*freenode) (void *));

/* compensating for
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
*/

// for inclusion of getaddrinfo etc.
#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0501

#include <ws2tcpip.h> // this includes winsock2.h, preventing inclusion of incompatible winsock.h
#include <stdio.h>

int memset_s(void *, int, size_t);
char* strtok_r(char *str, const char *delim, char **nextp);

#undef  INT64_MAX
#define HAVE_STDINT 1

#define sleep(x) Sleep((x) * 1000)

static inline void flockfile (FILE * filehandle)
{
    	return;
}
static inline void funlockfile (FILE * filehandle)
{
    	return;
}

#define SIGPIPE NSIG // dummy

//http://sourceforge.net/p/mingw/bugs/1641/
INT WSAAPI inet_pton (
 int Family,
 char * pszAddrString,
 void *pAddrBuf
);

//http://sourceforge.net/p/mingw/bugs/2147/
const char* inet_ntop(int af, const void *src, char *dst, DWORD size);

#define REPLACE_GETOPT 1
extern int	opterr;
extern int	optind;
extern int	optopt;
extern int	optreset;
extern char    *optarg;

DWORD WINAPI GetCurrentThreadId(void);
#endif

#endif

#endif
