/*------------------------------------------------------------------
 * utils.c - Generic functions used by all the example apps
 *
 * August, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
// Copyright (c) 2014 Siemens AG, 2014
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 *------------------------------------------------------------------
 */

// 2015-08-28 minor stability improvements
// 2014-06-25 improved logging of server main activity

#include <stdio.h>
#include <stdlib.h>

/*
 * Reads a file into an unsigned char array.
 * The array should not be allocated prior to calling this
 * function.  The return value is the size of the file
 * read into the array.
 */
int read_binary_file (char *filename, unsigned char **contents)
{
    FILE *fp;
    int len;

    fp = fopen(filename, "rb");
    if (!fp) {
	printf("\nUnable to open %s for reading\n", filename);
	return -1;
    }

    /*
     * Determine the size of the file
     */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *contents = (unsigned char *)malloc(len + 1);
    if (!*contents) {
	printf("\nmalloc fail\n");
        fclose(fp);
	return -2;
    }

    if (1 != fread(*contents, len, 1, fp)) {
	printf("\nfread failed\n");
        fclose(fp);
	return -2;
    }
    
    /*
     * put the terminator at the end of the buffer
     */
    *(*contents+len) = 0x00;
    fclose(fp);
    return (len);
}

/*
 * Generic function to write a binary file from
 * raw data.
 */
int write_binary_file (char *filename, unsigned char *contents, int len)
{
    FILE *fp;

    fp = fopen(filename, "wb");
    if (!fp) {
	printf("\nUnable to open %s for writing\n", filename);
	return -1;
    }
    fwrite(contents, sizeof(char), len, fp);
    fclose(fp);
    return 0;
}

/*
 * Simple function to display hex data to stdout
 * This is used for debugging
 */
void dumpbin (unsigned char *buf, size_t len)
{
    size_t i;

    printf("\ndumpbin (%lu bytes):\n", (long unsigned)len);
    for (i = 0; i < len; i++) {
        /*if (buf[i] >= 0xA)*/ printf("%c", buf[i]);
        //if (i%32 == 31) printf("\n");
    }
    //printf("\n");
    fflush(stdout);
}



