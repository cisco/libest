/*------------------------------------------------------------------
 * test_utils.h - General purpose utilities used by all the test code
 *
 * June, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#define LOG_FUNC_NM \
    do { \
	printf("\nEnter function %s\n", __FUNCTION__); \
	fflush(stdout); \
    } while (0)

int read_binary_file(char *filename, unsigned char **contents);
int write_binary_file(char *filename, unsigned char *contents, int len); 
BIO *open_tcp_socket(char *ipaddr, char *port);

#endif

