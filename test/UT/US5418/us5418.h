/*------------------------------------------------------------------
 * us5418.h - Header for User Story 5418 Tests - Performance Timers
 *  Contains the defines and includes common to both the coap and http suites
 *  for US5418 
 *
 * September, 2019
 *
 * Copyright (c) 2019 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
/*
 *
 */
#ifndef US5418_H
#define US5418_H
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <est.h>

#include "st_server.h"
#include "test_utils.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Automated.h"
#include "CUnit/Basic.h"
#endif

#define EST_UT_MAX_CMD_LEN 512
#define PARSE_TIMER_PATH "../util/parseTimers.py"
#define US5418_CSSL_NOT_SET_MSG                                                \
    "The path for the openssl installation used by"                            \
    " the python emulator was not specified.\n Please set the environment "    \
    "variable"                                                                 \
    " COAP_EMU_SSL"

#define MAX_FILENAME_LEN 256

#ifndef WIN32
#define US5418_CACERTS "CA/estCA/cacert.crt"
#define US5418_OPENSSL_CNF "CA/estExampleCA.cnf"
#define US5418_TRUSTED_CERT "CA/trustedcerts.crt"
#define US5418_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#else
#define US5418_CACERTS "CA\\estCA\\cacert.crt"
#define US5418_OPENSSL_CNF "CA\\estExampleCA.cnf"
#define US5418_TRUSTED_CERT "CA\\trustedcerts.crt"
#define US5418_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#endif
#define US5418_CLIENT_CERTKEY US5418_SERVER_CERT_AND_KEY
#define US5418_CLIENT_CACERTS US5418_CACERTS
#define PRINT_START                                                            \
    char success = 1;                                                          \
    printf("\nStarting test %s\n", __func__);
#define CU_FAIL_5418(x)                                                        \
    success &= 0;                                                              \
    printf(x);                                                                 \
    CU_FAIL(x);
#define CU_ASSERT_5418(x)                                                      \
    success &= (x);                                                            \
    CU_ASSERT(x);
#define PRINT_END                                                              \
    printf("\nTest %s %s\n", __func__, success ? "PASSED" : "*FAILED*");

#define US5418_SERVER_IP "127.0.0.1"
#define US5418_SERVER_PORT 29001

#define FOREACH_REQUESTS(E) \
    E(SIMPLE_ENROLL)\
    E(GET_CACERTS)\
    E(CSR_ATTRS)\
    E(SERVER_KEYGEN)\
    E(SIMPLE_REENROLL)
typedef enum  {
  FOREACH_REQUESTS(GENERATE_ENUM)
  MAX_REQ
} REQUESTS;
#define REQUESTS_TO_STR(x) request_type_str[x]

#define HEADER_LINE_COUNT 1
#endif /* US5418_H */