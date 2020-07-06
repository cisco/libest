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
 * Based on node-formidable by Felix Geisendörfer
 * Igor Afonov - afonov@gmail.com - 2012
 * MIT License - http://www.opensource.org/licenses/mit-license.php
 */

#include "multipart_parser.h"
#include "safe_mem_lib.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static void multipart_log(const char * format, ...)
{
#ifdef DEBUG_MULTIPART
    va_list args;
    va_start(args, format);

    fprintf(stderr, "[HTTP_MULTIPART_PARSER] %s:%d: ", __FILE__, __LINE__);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
#endif
}

#define NOTIFY_CB(FOR)                                                 \
do {                                                                   \
  if (p->settings->on_##FOR) {                                         \
    if (p->settings->on_##FOR(p) != 0) {                               \
      return i;                                                        \
    }                                                                  \
  }                                                                    \
} while (0)

#define EMIT_DATA_CB(FOR, ptr, len)                                    \
do {                                                                   \
  if (p->settings->on_##FOR) {                                         \
    if (p->settings->on_##FOR(p, ptr, len) != 0) {                     \
      return i;                                                        \
    }                                                                  \
  }                                                                    \
} while (0)


#define LF 10
#define CR 13
typedef struct {
    char *name;          // HTTP header name
    char *value;         // HTTP header value
} HTTP_HEADER;
#define MAX_HEADERS 16

struct multipart_parser {
  void * data;

  size_t index;
  size_t boundary_length;

  unsigned char state;

  const multipart_parser_settings* settings;

  int num_headers;
  HTTP_HEADER hdrs[MAX_HEADERS];

    char lookbehind[70];
  char multipart_boundary[70];

    char key_data[MULTIPART_PARSE_DATA_MAX];
    int key_data_len;
    char cert_data[MULTIPART_PARSE_DATA_MAX];

    int cert_data_len;
    int expected_payloads;
};

enum state {
  s_uninitialized = 1,
  s_start,
  s_start_boundary,
  s_header_field_start,
  s_header_field,
  s_headers_almost_done,
  s_header_value_start,
  s_header_value,
  s_header_value_almost_done,
  s_part_data_start,
  s_part_data,
  s_part_data_almost_boundary,
  s_part_data_boundary,
  s_part_data_almost_end,
  s_part_data_end,
  s_part_data_final_hyphen,
  s_end
};

multipart_parser* multipart_parser_init
    (const char *boundary, const multipart_parser_settings* settings) {

  multipart_parser* p = malloc(sizeof(multipart_parser) +
                               strlen(boundary) +
                               strlen(boundary) + 9);

  strcpy(p->multipart_boundary, boundary);
  p->boundary_length = strlen(boundary);

  p->index = 0;
  p->state = s_start;
  p->settings = settings;

  p->num_headers = 0;
    p->cert_data_len = 0;
    p->key_data_len = 0;
    p->expected_payloads = 2; // for EST server generated key resp

  return p;
}

void multipart_parser_free(multipart_parser* p) {
    if (p) {
        memzero_s(p->key_data, p->key_data_len);
        free(p);
    }
}

void multipart_parser_set_data(multipart_parser *p, void *data) {
    p->data = data;
}

void *multipart_parser_get_data(multipart_parser *p) {
    return p->data;
}

void *multipart_parser_get_hdrs(multipart_parser *p) {
  return p->hdrs;
}

void multipart_parser_increment_num_hdrs(multipart_parser *p) {
    p->num_headers++;
}

void multipart_parser_set_hdr_name(multipart_parser *p, char *name) {
    p->hdrs[p->num_headers].name = name;
}

int multipart_parser_set_hdr_value(multipart_parser *p, char *value) {
    char *header_name = p->hdrs[p->num_headers].name;
    if (!strncmp(header_name, "Content-Type", 12)) {
        if (!strncmp(value, "application/pkcs8", 17) ||
            !strncmp(value, "application/pkcs7-mime; smime-type=certs-only", 45)) {
            goto end;
        } else {
            goto error;
        }
    } else if (!strncmp(header_name, "Content-Transfer-Encoding", 25)) {
        if (!strncmp(value, "base64", 6)) {
            goto end;
        } else {
            goto error;
        }
    } else {
        goto error;
    }

    end:
    p->hdrs[p->num_headers].value = value;
    p->num_headers++;
    return 1;

    error:
    p->hdrs[p->num_headers].name = NULL;
    return -1;
}

void multipart_reset_hdrs(multipart_parser *p) {
    p->num_headers = 0;
}

char *multipart_get_data_ct(multipart_parser *p) {
    int i;
    for (i = 0; i < p->num_headers; i++) {
        multipart_log("header at %d is %s %s", i, p->hdrs[p->num_headers-i-1].name, p->hdrs[p->num_headers-i-1].value);
        if (strncmp(p->hdrs[p->num_headers-i-1].name, "Content-Type", 12) == 0) {
            return p->hdrs[p->num_headers-i-1].value;
        }
    }
    return NULL;
}

char *multipart_get_data_cte(multipart_parser *p) {
    int i;
    for (i = 0; i < p->num_headers; i++) {
        multipart_log("header at %d is %s %s", i, p->hdrs[p->num_headers-i-1].name, p->hdrs[p->num_headers-i-1].value);
        if (strncmp(p->hdrs[p->num_headers-i-1].name, "Content-Transfer-Encoding", 25) == 0) {
            return p->hdrs[p->num_headers-i-1].value;
        }
    }
    return NULL;
}

void multipart_set_key_data(multipart_parser *p, const char *data, int data_len) {
    memcpy_s(p->key_data, data_len, data, data_len);
    p->key_data_len = data_len;
}

void multipart_set_cert_data(multipart_parser *p, const char *data, int data_len) {
    memcpy_s(p->cert_data, data_len, data, data_len);
    p->cert_data_len = data_len;
}

int multipart_get_key_data(multipart_parser *p, unsigned char **key_data) {
    *key_data = calloc(p->key_data_len, sizeof(char));
    memcpy_s(*key_data, p->key_data_len, p->key_data, p->key_data_len);
    return p->key_data_len;
}

int multipart_get_cert_data(multipart_parser *p, unsigned char **cert_data) {
    *cert_data = calloc(p->cert_data_len, sizeof(char));
    memcpy_s(*cert_data, p->cert_data_len, p->cert_data, p->cert_data_len);
    return p->cert_data_len;
}

int multipart_parser_both_key_and_cert_populated(multipart_parser *p) {
    if (p->cert_data_len && p->key_data_len) {
        return 1;
    }
    return 0;
}

size_t multipart_parser_execute(multipart_parser* p, const char *buf, size_t len) {
  size_t i = 0;
  size_t mark = 0;
  char c, cl;
  int is_last = 0, seen_headers = 0, seen_hdr_delimiter = 0,
          num_payloads = 0;

    while((buf[0]) == '-') {
        buf++;
    }

  while(i < len) {
    c = buf[i];
    multipart_log("%c", c);
    is_last = (i == (len - 1));
    switch (p->state) {
      case s_start:
        multipart_log("s_start");
        p->index = 0;
        p->state = s_start_boundary;

      /* fallthrough */
      case s_start_boundary:
        multipart_log("s_start_boundary %d", p->index);
        if (p->index == p->boundary_length) {
          if (c != CR) {
              multipart_log("c!=CR");
              if (c == '-') {
                  p->state = s_part_data_final_hyphen;
              } else {
                  return i;
              }
          }
          p->index++;
          break;
        } else if (p->index == (p->boundary_length + 1)) {
          if (c != LF) {
              multipart_log("c!=LF %d", p->index);
              return i;
          }
          p->index = 0;
          NOTIFY_CB(part_data_begin);
          p->state = s_header_field_start;
          seen_headers = 0;
          break;
        }

        p->index++;
        break;

      case s_header_field_start:
        multipart_log("s_header_field_start");
        mark = i;
        p->state = s_header_field;

      /* fallthrough */
      case s_header_field:
        multipart_log("s_header_field");
        if (c == CR) {
          p->state = s_headers_almost_done;
          break;
        }
        if (c == ':') {
          seen_headers = 1;
          seen_hdr_delimiter = 1;
          EMIT_DATA_CB(header_field, buf + mark, i - mark);
          p->state = s_header_value_start;
          break;
        }
        if ((i - mark) > 63 && !seen_hdr_delimiter) {
            return 0;
        }

        cl = tolower(c);
        if ((c != '-') && (cl < 'a' || cl > 'z')) {
          multipart_log("invalid character in header name");
          return i;
        }
        if (is_last) {
            EMIT_DATA_CB(header_field, buf + mark, (i - mark) + 1);
        }
        break;

      case s_headers_almost_done:
        multipart_log("s_headers_almost_done");
        if (c != LF) {
          return i;
        }
        if (seen_headers) {
            p->state = s_part_data_start;
        } else {
            p->state = s_header_field_start;
        }
        break;

      case s_header_value_start:
        multipart_log("s_header_value_start");
        if (c == ' ') {
          break;
        }

        mark = i;
        p->state = s_header_value;

      /* fallthrough */
      case s_header_value:
        seen_hdr_delimiter = 0;
        multipart_log("s_header_value");
        if (c == CR) {
          EMIT_DATA_CB(header_value, buf + mark, i - mark);
          p->state = s_header_value_almost_done;
          break;
        }
        if (is_last) {
            EMIT_DATA_CB(header_value, buf + mark, (i - mark) + 1);
        }
        break;

      case s_header_value_almost_done:
        multipart_log("s_header_value_almost_done");
        if (c != LF) {
          return i;
        }
        if (buf[i+1] == '-') {
            p->state = s_start_boundary;
            i+=2;
        } else {
            p->state = s_header_field_start;
        }
        break;

      case s_part_data_start:
        multipart_log("s_part_data_start");
        NOTIFY_CB(headers_complete);
        mark = i;
        p->state = s_part_data;

      /* fallthrough */
      case s_part_data:
        multipart_log("s_part_data");
        if (c == CR) {
            if (buf[i+1] == '-' || buf[i+2] == '-') {
                num_payloads++;
                EMIT_DATA_CB(part_data, buf + mark, i - mark);
                mark = i;
                p->state = s_part_data_almost_boundary;
                p->lookbehind[0] = CR;
                break;
            }
        }
        if (is_last) {
            EMIT_DATA_CB(part_data, buf + mark, (i - mark) + 1);
        }
        break;

      case s_part_data_almost_boundary:
        multipart_log("s_part_data_almost_boundary");
        if (c == LF) {
            if (num_payloads == p->expected_payloads) {
                p->state = s_part_data_boundary;
            } else {
                p->state = s_start_boundary;
            }
            p->lookbehind[1] = LF;
            p->index = 0;
            i+=2;
            break;
        }
        EMIT_DATA_CB(part_data, p->lookbehind, 1);
        p->state = s_part_data;
        mark = i --;
        break;

      case s_part_data_boundary:
        multipart_log("s_part_data_boundary");
        if (p->multipart_boundary[p->index] != c) {
            EMIT_DATA_CB(part_data, p->lookbehind, 2 + p->index);
            p->state = s_header_field_start;
            mark = i --;
            break;
        }
        p->lookbehind[2 + p->index] = c;
        if ((++ p->index) == p->boundary_length) {
            NOTIFY_CB(part_data_end);
            p->state = s_part_data_almost_end;
        }
        break;

      case s_part_data_almost_end:
        multipart_log("s_part_data_almost_end");
        if (c == '-') {
            p->state = s_part_data_final_hyphen;
            break;
        }
        if (c == CR) {
            p->state = s_part_data_end;
            break;
        }
        return i;
   
      case s_part_data_final_hyphen:
        multipart_log("s_part_data_final_hyphen");
        if (c == '-') {
            NOTIFY_CB(body_end);
            p->state = s_end;
            break;
        }
        return i;

      case s_part_data_end:
        multipart_log("s_part_data_end");
        if (c == LF) {
            p->state = s_header_field_start;
            NOTIFY_CB(part_data_begin);
            break;
        }
        return i;

      case s_end:
        multipart_log("s_end: %02X", (int) c);
        break;

      default:
        multipart_log("Multipart parser unrecoverable error");
        return 0;
    }
    ++ i;
  }

  return len;
}
