/*------------------------------------------------------------------
 * est_sock_compat.h - Socket Compatibility
 *
 * For socket compatibility between Windows and every other
 * target
 *
 * April, 2016
 *
 * Copyright (c) 2016 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
#ifndef HEADER_EST_SOCK_COMPAT_H
#define HEADER_EST_SOCK_COMPAT_H

#ifdef WIN32
    /*
     * Winsock defines a different function for closing sockets because not all
     * versions of Windows have file descriptor and socket descriptor
     * equivalency like Unix.  To make sure we call the right function, use the
     * CLOSE_SOCKET macro for closing the socket
     */
#   define  CLOSE_SOCKET(s)        closesocket(s)
#   define  SOCK_TYPE              SOCKET
#   define  SOCK_INVALID           INVALID_SOCKET
#   define  GET_SOCK_ERR()         WSAGetLastError()
#   define  SET_SOCK_ERR(e)        WSASetLastError(e)
#   define  SET_SOCK_ERR_NONAME()  WSASetLastError(WSAHOST_NOT_FOUND)
#   define  SET_SOCK_ERR_CONN()    WSASetLastError(WSAECONNREFUSED)
#   define  SET_SOCK_ERR_NOMEM()   WSASetLastError(WSA_NOT_ENOUGH_MEMORY)
#else
#   define  CLOSE_SOCKET(s)        close(s)
#   define  SOCK_TYPE              int
#   define  SOCK_INVALID           -1
#   define  GET_SOCK_ERR()         errno
#   define  SET_SOCK_ERR(e)        { errno = (e); }
#   define  SET_SOCK_ERR_NONAME()  { errno = ENOENT; }
#   define  SET_SOCK_ERR_CONN()    { errno = ECONNREFUSED; }
#   define  SET_SOCK_ERR_NOMEM()   { errno = ENOMEM; }
#endif /* WIN32 */

#endif /* HEADER_EST_SOCK_COMPAT_H */
