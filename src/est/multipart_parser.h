/*
 * HTTP Multipart parser
 *
 * Based on open source parser at:
 * https://github.com/iafonov/multipart-parser-c/
 *
 * Updated 2018 by Cisco
 *
 * ---------------------------------------
 *
 *
 * Based on node-formidable by Felix Geisendörfer
 * Igor Afonov - afonov@gmail.com - 2012
 * MIT License - http://www.opensource.org/licenses/mit-license.php
 */
#ifndef _multipart_parser_h
#define _multipart_parser_h

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <ctype.h>

typedef struct multipart_parser multipart_parser;
typedef struct multipart_parser_settings multipart_parser_settings;
typedef struct multipart_parser_state multipart_parser_state;

typedef int (*multipart_data_cb) (multipart_parser*, const char *at, size_t length);
typedef int (*multipart_notify_cb) (multipart_parser*);

#define MULTIPART_PARSE_DATA_MAX 8192

struct multipart_parser_settings {
  multipart_data_cb on_header_field;
  multipart_data_cb on_header_value;
  multipart_data_cb on_part_data;

  multipart_notify_cb on_part_data_begin;
  multipart_notify_cb on_headers_complete;
  multipart_notify_cb on_part_data_end;
  multipart_notify_cb on_body_end;
};

multipart_parser* multipart_parser_init
    (const char *boundary, const multipart_parser_settings* settings);

void multipart_parser_free(multipart_parser* p);

size_t multipart_parser_execute(multipart_parser* p, const char *buf, size_t len);

void multipart_parser_set_data(multipart_parser* p, void* data);
void *multipart_parser_get_data(multipart_parser* p);
void *multipart_parser_get_hdrs(multipart_parser *p);
void multipart_parser_increment_num_hdrs(multipart_parser *p);
void multipart_parser_set_hdr_name(multipart_parser *p, char *name);
int multipart_parser_set_hdr_value(multipart_parser *p, char *value);
char *multipart_get_data_ct(multipart_parser *p);
char *multipart_get_data_cte(multipart_parser *p);
void multipart_reset_hdrs(multipart_parser *p);
void multipart_set_key_data(multipart_parser *p, const char *data, int data_len);
void multipart_set_cert_data(multipart_parser *p, const char *data, int data_len);
int multipart_get_key_data(multipart_parser *p, unsigned char **key_data);
int multipart_get_cert_data(multipart_parser *p, unsigned char **cert_data);
int multipart_parser_both_key_and_cert_populated(multipart_parser *p);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
