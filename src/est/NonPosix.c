/*------------------------------------------------------------------
 * est/NonPosix.c - POSIX compensation layer for, e.g., Windows and QNX
 * Copyright (c) 2014 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

#include "NonPosix.h"
#include <stdio.h>

#ifdef _WIN32

#include <openssl/../../ms/applink.c> // prevents runtime error OPENSSL_Uplink(10111000,08): no OPENSSL_Applink

#ifndef DISABLE_TSEARCH

//https://chromium.googlesource.com/native_client/nacl-newlib/+/master/newlib/libc/search/tdestroy.c
#ifndef _SEARCH_PRIVATE
typedef struct node {
	char         *key;
	struct node  *llink, *rlink;
} node_t;
#endif

/* Walk the nodes of a tree */
static void trecurse(node_t *root, void (*free_action)(void *))
{
  if (root->llink != NULL)
    trecurse(root->llink, free_action);
  if (root->rlink != NULL)
    trecurse(root->rlink, free_action);
  (*free_action) ((void *) root->key);
  free(root);
}
void tdestroy (void *vrootp, void (*freefct)(void *))
{
  node_t *root = (node_t *) vrootp;
  if (root != NULL)
    trecurse(root, freefct);
}

#ifdef _MSC_VER
//adapted from https://sourceforge.net/p/vapor/git/ci/master/tree/lib/udunits2/tsearch.c
/*
 * Tree search generalized from Knuth (6.2.2) Algorithm T just like
 * the AT&T man page says.
 *
 * The node structure is for internal use only, lint doesn't grok it.
 *
 * Written by reading the System V Interface Definition, not the code.
 *
 * Totally public domain.
 */
/*LINTLIBRARY*/

/* find or insert datum into search tree */
void *tsearch(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *))
{
    node_t *q;
    char *key = (char *)vkey;
    node_t **rootp = (node_t **)vrootp;

    if (rootp == (node_t **)0)
	return ((void *)0);
    while (*rootp != (node_t *)0) {	/* Knuth's T1: */
	int r;

	if ((r = (*compar)(key, (*rootp)->key)) == 0)	/* T2: */
	    return ((void *)*rootp);		/* we found it! */
	rootp = (r < 0) ?
	    &(*rootp)->llink :		/* T3: follow left branch */
	    &(*rootp)->rlink;		/* T4: follow right branch */
    }
    q = (node_t *) malloc(sizeof(node));/* T5: key not found */
    if (q != (node_t *)0) {		/* make new node */
	*rootp = q;			/* link new node to old */
	q->key = key;			/* initialize new node */
	q->llink = q->rlink = (node_t *)0;
    }
    return ((void *)q);
}

/* find datum in search tree */
void *tfind(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *))
{

    char *key = (char *)vkey;
    node_t **rootp = (node_t **)vrootp;

    if (rootp == (node_t **)0)
	return ((void *)0);
    while (*rootp != (node_t *)0) {		/* Knuth's T1: */
	int r;

	if ((r = (*compar)(key, (*rootp)->key)) == 0)	/* T2: */
	    return ((void *)*rootp);		/* we found it! */
	rootp = (r < 0) ?
	    &(*rootp)->llink :			/* T3: follow left branch */
	    &(*rootp)->rlink;			/* T4: follow right branch */
    }
    return ((void *)0);	/* T5: key not found */
}

/* delete node with given key */
void *
tdelete(const void *vkey, void **vrootp,
    int (*compar)(const void *, const void *))
{
    node_t **rootp = (node_t **)vrootp;
    char *key = (char *)vkey;
    node_t *p = (node_t *)1;
    node_t *q;
    node_t *r;
    int cmp;

    if (rootp == (node_t **)0 || *rootp == (node_t *)0)
	return ((node_t *)0);
    while ((cmp = (*compar)(key, (*rootp)->key)) != 0) {
	p = *rootp;
	rootp = (cmp < 0) ?
	    &(*rootp)->llink :		/* follow left branch */
	    &(*rootp)->rlink;		/* follow right branch */
	if (*rootp == (node_t *)0)
	    return ((void *)0);		/* key not found */
    }
    r = (*rootp)->rlink;			/* D1: */
    if ((q = (*rootp)->llink) == (node_t *)0)	/* Left (node_t *)0? */
	q = r;
    else if (r != (node_t *)0) {		/* Right link is null? */
	if (r->llink == (node_t *)0) {		/* D2: Find successor */
	    r->llink = q;
	    q = r;
	} else {				/* D3: Find (node_t *)0 link */
	    for (q = r->llink; q->llink != (node_t *)0; q = r->llink)
		r = q;
	    r->llink = q->rlink;
	    q->llink = (*rootp)->llink;
	    q->rlink = (*rootp)->rlink;
	}
    }
    free((node_t *) *rootp);		/* D4: Free node */
    *rootp = q;				/* link parent to new node */
    return(p);
}
#endif // _MSC_VER

#endif // DISABLE_TSEARCH

#include <ctype.h>
int strncasecmp (const char *s1, const char *s2, size_t n)
{
  if (n == 0)
    return 0;

  while (n-- != 0 && tolower(*s1) == tolower(*s2))
    {
      if (n == 0 || *s1 == '\0' || *s2 == '\0')
    break;
      s1++;
      s2++;
    }

  return tolower(*(unsigned char *) s1) - tolower(*(unsigned char *) s2);
}

char* strtok_r(
    char *str, 
    const char *delim, 
    char **nextp)
{
    char *ret;

    if (str == NULL)
    {
        str = *nextp;
    }

    str += strspn(str, delim);

    if (*str == '\0')
    {
        return NULL;
    }

    ret = str;

    str += strcspn(str, delim);

    if (*str)
    {
        *str++ = '\0';
    }

    *nextp = str;

    return ret;
}

#if defined(__MINGW32__) // || defined(_MSC_VER)
//http://stackoverflow.com/questions/13731243/what-is-the-windows-xp-equivalent-of-inet-pton-or-inetpton
int inet_pton(int af, const char *src, void *dst)
{
  struct sockaddr_storage ss;
  int size = sizeof(ss);

  ZeroMemory(&ss, sizeof(ss));

  if (WSAStringToAddress((LPTSTR)src, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
    switch(af) {
      case AF_INET:
    *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
    return 1;
      case AF_INET6:
    *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
    return 1;
    }
  }
  return 0;
}

//http://memset.wordpress.com/2010/10/09/inet_ntop-for-win32/
//http://msdn.microsoft.com/en-us/library/windows/desktop/ms742213%28v=vs.85%29.aspx
const char* inet_ntop(int af, const void* src, char* dst, DWORD cnt) {
  /*
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2); // 2.2

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return NULL;
    }
 */
    struct sockaddr_in srcaddr;
 
    memset(&srcaddr, 0, sizeof(struct sockaddr_in));
    memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));
 
    srcaddr.sin_family = af;
    if (WSAAddressToString((struct sockaddr*) &srcaddr, sizeof(struct sockaddr_in), 0, dst, &cnt) != 0) {
        DWORD rv = WSAGetLastError();
        printf("WSAAddressToString() : %ld\n",rv);
        dst = NULL;
    }
    //WSACleanup();
    return dst;
}
#endif

//http://code.ohloh.net/file?fid=LSpuD5qHojGNKIErA1OPY3EMW_I&cid=XvB8n8Wal3c&s=
/*
 * Simple implementation of C11 memset_s() function.
 * We use a volatile pointer when updating the byte string.
 * Most compilers will avoid optimizing away access to a
 * volatile pointer, even if the pointer appears to be unused
 * after the call.
 *
 * Note that C11 does not specify the return value on error, only
 * that it be non-zero.  We use EINVAL for all errors.
 */
#include <errno.h>
int memset_s(void *v, int c, size_t n)
{
    int ret = 0;
    volatile unsigned char *s = (volatile unsigned char *)v;

    /* Fatal runtime-constraint violations. */
    if (s == NULL) {
	ret = errno = EINVAL;
	goto done;
    }
    /* Updating through a volatile pointer should not be optimized away. */
    while (n--)
	*s++ = (unsigned char)c;
done:
    return ret;
}
#endif // defined(_WIN32)


#if defined(_WIN32) || defined (QNX650_)

#if 0
#include <backtrace.h>
//unused: print_backtrace();
void print_backtrace (void) {

  char out[1024];
  bt_addr_t pc[16];
  bt_accessor_t acc;
  bt_memmap_t memmap;
  int i;
  int cnt;
  
  //bt_init_accessor(&acc, BT_PROCESS, remotepid, remotetid);
  bt_init_accessor(&acc, BT_SELF);
  bt_load_memmap(&acc, &memmap);
  bt_sprn_memmap(&acc, out, sizeof(out));
  
  for (i=0; i<10; i++) {
    cnt=bt_get_backtrace(&acc, pc, sizeof(pc)/sizeof(bt_addr_t));
    bt_sprnf_addrs(&memmap, pc, cnt, "%a\n", out, sizeof(out), 0);
    puts(out);
  }
  bt_unload_memmap(&memmap);
  bt_release_accessor(&acc);
}
#endif


#include <stdlib.h>
#include <string.h>
// QNX 6.5 needs a definition, taken from http://unixpapa.com/incnote/string.html
  #ifndef HAVE_STRNDUP
  #define HAVE_STRNDUP
  char *strndup(const char *str, size_t len)
  {
      char *dup= (char *)malloc( len+1 );
      if (dup) {
          strncpy(dup,str,len);
          dup[len]= '\0';
      }
      return dup;
   }
   #endif

// QNX 6.5 needs a definition, taken from http://unixpapa.com/incnote/string.html
       #ifndef HAVE_STRNLEN
       #define HAVE_STRNLEN
       size_t strnlen(const char *s, size_t maxlen)
       {
    	size_t i;

    	for (i= 0; i < maxlen && *s != '\0'; i++, s++)
    	    ;
    	return i;
       }
       #endif
#endif // defined(_MINWG) || defined (QNX650_)


#ifdef _MSC_VER
// from http://cvsweb.netbsd.org/bsdweb.cgi/~checkout~/pkgsrc/devel/libgetopt/files/getopt_long.c?rev=1.4&content-type=text/plain

/*	$NetBSD: getopt_long.c,v 1.4 2011/09/07 00:56:17 joerg Exp $	*/

/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _DIAGASSERT
#define _DIAGASSERT(e)
#endif

#ifdef REPLACE_GETOPT
int	opterr = 1;		/* if error message should be printed */
int	optind = 1;		/* index into parent argv vector */
int	optopt = '?';		/* character checked for validity */
int	optreset;		/* reset getopt */
char    *optarg;		/* argument associated with option */
#endif

#define IGNORE_FIRST	(*options == '-' || *options == '+')
#define PRINT_ERROR	((opterr) && ((*options != ':') \
				      || (IGNORE_FIRST && options[1] != ':')))
#define IS_POSIXLY_CORRECT (getenv("POSIXLY_CORRECT") != NULL)
#define PERMUTE         (!IS_POSIXLY_CORRECT && !IGNORE_FIRST)
/* XXX: GNU ignores PC if *options == '-' */
#define IN_ORDER        (!IS_POSIXLY_CORRECT && *options == '-')

/* return values */
#define	BADCH	(int)'?'
#define	BADARG	(int)':'
#define INORDER (int)1

#define	EMSG	""

static int getopt_internal(int, char * const *, const char *);
static int gcd(int, int);
static void permute_args(int, int, int, char * const *);
static void xwarnx(const char *, ...);

static char *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static int nonopt_start = -1; /* first non option argument (for permute) */
static int nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
static const char recargchar[] = "option requires an argument -- %c";
static const char recargstring[] = "option requires an argument -- %s";
static const char ambig[] = "ambiguous option -- %.*s";
static const char noarg[] = "option doesn't take an argument -- %.*s";
static const char illoptchar[] = "illegal option -- %c";
static const char illoptstring[] = "illegal option -- %s";

static const char *progname;


/* Replacement for warnx(3) for systems without it. */
static void xwarnx(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	if (progname)
		(void) fprintf(stderr, "%s: ", progname);
	if (fmt)
		(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}

/*
 * Compute the greatest common divisor of a and b.
 */
static int gcd(int a, int b)
{
	int c;

	c = a % b;
	while (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}
	   
	return b;
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void permute_args(int nonopt_start, int nonopt_end, int opt_end, char * const *nargv)
{
	int cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	char *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = nonopt_end - nonopt_start;
	nopts = opt_end - nonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - nonopt_start) / ncycle;

	for (i = 0; i < ncycle; i++) {
		cstart = nonopt_end+i;
		pos = cstart;
		for (j = 0; j < cyclelen; j++) {
			if (pos >= nonopt_end)
				pos -= nnonopts;
			else
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((char **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((char **)nargv)[cstart] = swap;
		}
	}
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 *  Returns -2 if -- is found (can be long option or end of options marker).
 */
static int getopt_internal(int nargc, char * const *nargv, const char *options)
{
	char *oli;				/* option letter list index */
	int optchar;

	_DIAGASSERT(nargv != NULL);
	_DIAGASSERT(options != NULL);

	optarg = NULL;

	/*
	 * XXX Some programs (like rsyncd) expect to be able to
	 * XXX re-initialize optind to 0 and have getopt_long(3)
	 * XXX properly function again.  Work around this braindamage.
	 */
	if (optind == 0)
		optind = 1;

	if (optreset)
		nonopt_start = nonopt_end = -1;
start:
	if (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		if (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			if (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			else if (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			return -1;
		}
		if (*(place = nargv[optind]) != '-') {  /* found non-option */
			place = EMSG;
			if (IN_ORDER) {
				/*
				 * GNU extension: 
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				return INORDER;
			}
			if (!PERMUTE) {
				/*
				 * if no permutation wanted, stop parsing
				 * at first non-option
				 */
				return -1;
			}
			/* do permutation */
			if (nonopt_start == -1)
				nonopt_start = optind;
			else if (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			goto start;
		}
		if (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;
		if (place[1] && *++place == '-') {	/* found "--" */
			place++;
			return -2;
		}
	}
	if ((optchar = (int)*place++) == (int)':' ||
	    (oli = strchr((char *)options + (IGNORE_FIRST ? 1 : 0), optchar)) == NULL) {
		/* option letter unknown or ':' */
		if (!*place)
			++optind;
		if (PRINT_ERROR)
			xwarnx(illoptchar, optchar);
		optopt = optchar;
		return BADCH;
	}
	if (optchar == 'W' && oli[1] == ';') {		/* -W long-option */
		/* XXX: what if no long options provided (called by getopt)? */
		if (*place) 
			return -2;

		if (++optind >= nargc) {	/* no arg */
			place = EMSG;
			if (PRINT_ERROR)
				xwarnx(recargchar, optchar);
			optopt = optchar;
			/* XXX: GNU returns '?' if options[0] != ':' */
			return BADARG;
		} else				/* white space */
			place = nargv[optind];
		/*
		 * Handle -W arg the same as --arg (which causes getopt to
		 * stop parsing).
		 */
		return -2;
	}
	if (*++oli != ':') {			/* doesn't take argument */
		if (!*place)
			++optind;
	} else {				/* takes (optional) argument */
		optarg = NULL;
		if (*place)			/* no white space */
			optarg = place;
		/* XXX: disable test for :: if PC? (GNU doesn't) */
		else if (oli[1] != ':') {	/* arg not optional */
			if (++optind >= nargc) {	/* no arg */
				place = EMSG;
				if (PRINT_ERROR)
					xwarnx(recargchar, optchar);
				optopt = optchar;
				/* XXX: GNU returns '?' if options[0] != ':' */
				return BADARG;
			} else
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	return optchar;
}

#ifdef REPLACE_GETOPT
/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the real getopt]
 */
int getopt(int nargc, char * const *nargv, const char *options)
{
	int retval;

	progname = nargv[0];

	if ((retval = getopt_internal(nargc, nargv, options)) == -2) {
		++optind;
		/*
		 * We found an option (--), so if we skipped non-options,
		 * we have to permute.
		 */
		if (nonopt_end != -1) {
			permute_args(nonopt_start, nonopt_end, optind,
				       nargv);
			optind -= nonopt_end - nonopt_start;
		}
		nonopt_start = nonopt_end = -1;
		retval = -1;
	}
	return retval;
}
#endif
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */

int getopt_long(int nargc, char * const *nargv, const char *options, const struct option *long_options, int *idx)
{
	int retval;

	_DIAGASSERT(nargv != NULL);
	_DIAGASSERT(options != NULL);
	_DIAGASSERT(long_options != NULL);
	/* idx may be NULL */

	progname = nargv[0];

	if ((retval = getopt_internal(nargc, nargv, options)) == -2) {
		char *current_argv, *has_equal;
		size_t current_argv_len;
		int i, match;

		current_argv = place;
		match = -1;

		optind++;
		place = EMSG;

		if (*current_argv == '\0') {		/* found "--" */
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			if (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			return -1;
		}
		if ((has_equal = strchr(current_argv, '=')) != NULL) {
			/* argument found (--option=arg) */
			current_argv_len = has_equal - current_argv;
			has_equal++;
		} else
			current_argv_len = strlen(current_argv);
	    
		for (i = 0; long_options[i].name; i++) {
			/* find matching long option */
			if (strncmp(current_argv, long_options[i].name,
			    current_argv_len))
				continue;

			if (strlen(long_options[i].name) ==
			    (unsigned)current_argv_len) {
				/* exact match */
				match = i;
				break;
			}
			if (match == -1)		/* partial match */
				match = i;
			else {
				/* ambiguous abbreviation */
				if (PRINT_ERROR)
					xwarnx(ambig, (int)current_argv_len,
					     current_argv);
				optopt = 0;
				return BADCH;
			}
		}
		if (match != -1) {			/* option found */
		        if (long_options[match].has_arg == no_argument
			    && has_equal) {
				if (PRINT_ERROR)
					xwarnx(noarg, (int)current_argv_len,
					     current_argv);
				/*
				 * XXX: GNU sets optopt to val regardless of
				 * flag
				 */
				if (long_options[match].flag == NULL)
					optopt = long_options[match].val;
				else
					optopt = 0;
				/* XXX: GNU returns '?' if options[0] != ':' */
				return BADARG;
			}
			if (long_options[match].has_arg == required_argument ||
			    long_options[match].has_arg == optional_argument) {
				if (has_equal)
					optarg = has_equal;
				else if (long_options[match].has_arg ==
				    required_argument) {
					/*
					 * optional argument doesn't use
					 * next nargv
					 */
					optarg = nargv[optind++];
				}
			}
			if ((long_options[match].has_arg == required_argument)
			    && (optarg == NULL)) {
				/*
				 * Missing argument; leading ':'
				 * indicates no error should be generated
				 */
				if (PRINT_ERROR)
					xwarnx(recargstring, current_argv);
				/*
				 * XXX: GNU sets optopt to val regardless
				 * of flag
				 */
				if (long_options[match].flag == NULL)
					optopt = long_options[match].val;
				else
					optopt = 0;
				/* XXX: GNU returns '?' if options[0] != ':' */
				--optind;
				return BADARG;
			}
		} else {			/* unknown option */
			if (PRINT_ERROR)
				xwarnx(illoptstring, current_argv);
			optopt = 0;
			return BADCH;
		}
		if (long_options[match].flag) {
			*long_options[match].flag = long_options[match].val;
			retval = 0;
		} else 
			retval = long_options[match].val;
		if (idx)
			*idx = match;
	}
	return retval;
}

#endif // _MSC_VER
