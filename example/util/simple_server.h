/*------------------------------------------------------------------
 * simple_server.h - This is a very simple multi-threaded TCP
 *                   server used by the example EST server and EST
 *                   proxy applications. 
 *
 * August, 2013
 *
 * Copyright (c) 2013-2014 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
#ifndef HEADER_SIMPLE_SERVER_H
#define HEADER_SIMPLE_SERVER_H
void start_simple_server(EST_CTX *ectx, int port, int delay, int v6);
#endif
