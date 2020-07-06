/*------------------------------------------------------------------
 * us895.c - Unit Tests for User Story 895 - Proxy CSR Attributes
 *
 * November, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <est.h>
#include <curl/curl.h>
#include "curl_utils.h"
#include "test_utils.h"
#include "st_server.h"
#include "st_proxy.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US895_SERVER_PORT   29895
#define US895_PROXY_PORT   29095

#ifndef WIN32
#define US895_CACERT        "CA/estCA/cacert.crt"
#define US895_TRUSTED_CERT  "CA/trustedcerts.crt"
#define SERVER_UT_CACERT    "CA/estCA/cacert.crt"
#define SERVER_UT_PUBKEY    "./est_client_ut_keypair"

#define US895_SERVER_IP     "127.0.0.1" 
#define US895_CACERTS       "CA/estCA/cacert.crt"
#define US895_TRUST_CERTS   "CA/trustedcerts.crt"
#define US895_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#else
#define US895_CACERT        "CA\\estCA\\cacert.crt"
#define US895_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define SERVER_UT_CACERT     "CA\\estCA\\cacert.crt"
#define SERVER_UT_PUBKEY    "est_client_ut_keypair"

#define US895_SERVER_IP     "127.0.0.1" 
#define US895_CACERTS       "CA\\estCA\\cacert.crt"
#define US895_TRUST_CERTS   "CA\\trustedcerts.crt"
#define US895_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#endif

#define TEST_ATTR_POP "MAsGCSqGSIb3DQEJBw==\0"
#define TEST_ATTR_NOPOP "MHEwLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBglghkgBZQMEAgIGCSskAwMCCAEBCzAiBgOINwExGxMZUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YQYHKwYBAQEBFg==\0"
#define TEST_ATTR_NOPOPPOP "MHwwLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBglghkgBZQMEAgIGCSskAwMCCAEBCzAiBgOINwExGxMZUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YQYHKwYBAQEBFgYJKoZIhvcNAQkH\0"
#define TEST_ATTR_POPADDED "MHwwLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBglghkgBZQMEAgIGCSskAwMCCAEBCzAiBgOINwExGxMZUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YQYHKwYBAQEBFgYJKoZIhvcNAQkH\0"
#define TEST_ATTR1 "MCYGBysGAQEBARYGCSqGSIb3DQEJBwYFK4EEACIGCWCGSAFlAwQCAg==\0"
#define TEST_ATTR2 "MAA=\0"
#define TEST_ATTR7 "MA==\0"
#define TEST_ATTR2_POP "MAsGCSqGSIb3DQEJBw==\0"
#define TEST_ATTR8 "MAthisis badsGCSqGSIb3DQEJBw==\0"
#define TEST_ATTR3 "MIGSMFgGA4g3AjFRExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhExlQYXJzZSBTRVQgYXMgMi45OTkuMyBkYXRhExlQYXJzZSBTRVQgYXMgMi45OTkuNCBkYXRhBgkqhkiG9w0BCQcwIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEGBysGAQEBARY=\0"
#define TEST_ATTR4_122 "MHowLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBglghkgBZQMEAgIGCSskAwMCCAEBCzAiBgOINwExGxMZUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YQYHKwYBAQEBFgYHKwYBAQEBFg==\0"
#define TEST_ATTR4_122POP "MIGFMCwGA4g3AjElBgOINwMGA4g3BBMZUGFyc2UgU0VUIGFzIDIuOTk5LjIgZGF0YQYJYIZIAWUDBAICBgkrJAMDAggBAQswIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEGBysGAQEBARYGBysGAQEBARYGCSqGSIb3DQEJBw==\0"
#define TEST_ATTR5_117 "MHUwJwYDiDcCMSAGA4g3AwYDiDcEExRQYXJzZSBTRVQgYXMgMi45OTkuMgYJYIZIAWUDBAICBgkrJAMDAggBAQswIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEGBysGAQEBARYGBysGAQEBARY=\0"
#define TEST_ATTR5_117POP "MIGAMCcGA4g3AjEgBgOINwMGA4g3BBMUUGFyc2UgU0VUIGFzIDIuOTk5LjIGCWCGSAFlAwQCAgYJKyQDAwIIAQELMCIGA4g3ATEbExlQYXJzZSBTRVQgYXMgMi45OTkuMSBkYXRhBgcrBgEBAQEWBgcrBgEBAQEWBgkqhkiG9w0BCQc=\0"
#define TEST_ATTR6_116 "MHQwJwYDiDcCMSAGA4g3AwYDiDcEExRQYXJzZSBTRVQgYXMgMi45OTkuMgYJYIZIAWUDBAICBgkrJAMDAggBAQswIQYDiDcBMRoTGFBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdAYHKwYBAQEBFgYHKwYBAQEBFg==\0"
#define TEST_ATTR_244 "MIH1MGQGA4g3AjFdBgOINwMGA4g3BBNRUGFyc2UgU0VUIGFzIDIuOTk5LjIgMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwBglghkgBZQMEAgIGCSskAwMCCAEBCzBlBgOINwExXhNcUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YSAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQGBysGAQEBARYGBysGAQEBARY=\0"
#define TEST_ATTR_245 "MIH2MGQGA4g3AjFdBgOINwMGA4g3BBNRUGFyc2UgU0VUIGFzIDIuOTk5LjIgMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwBglghkgBZQMEAgIGCSskAwMCCAEBCzBmBgOINwExXxNdUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YSAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1BgcrBgEBAQEWBgcrBgEBAQEW\0"
#define TEST_ATTR_250 "MIH7MGQGA4g3AjFdBgOINwMGA4g3BBNRUGFyc2UgU0VUIGFzIDIuOTk5LjIgMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwBglghkgBZQMEAgIGCSskAwMCCAEBCzBrBgOINwExZBNiUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YSAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1MTIzNDUGBysGAQEBARYGBysGAQEBARY=\0"
#define TEST_ATTR_250POP "MIIBBjBkBgOINwIxXQYDiDcDBgOINwQTUVBhcnNlIFNFVCBhcyAyLjk5OS4yIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MAYJYIZIAWUDBAICBgkrJAMDAggBAQswawYDiDcBMWQTYlBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEgMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwYWIxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTEyMzQ1BgcrBgEBAQEWBgcrBgEBAQEWBgkqhkiG9w0BCQc=\0"
#define TEST_ALL_ATTR "MIHTMIGBBgOINwIxegEB/wICAP8GA4g3AwYDiDcECgECEhAxMjM0NTY3ODkwQUJDREVGExRQYXJzZSBTRVQgYXMgMi45OTkuMhQFMTIzNDUUBTEyMzQ1FgUxMjM0NRoFMTIzNDUcFAAAADEAAAAyAAAAMwAAADQAAAA1HgoAMQAyADMANAA1BglghkgBZQMEAgIGCSskAwMCCAEBCzAiBgOINwExGxMZUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YQYHKwYBAQEBFgYHKwYBAQEBFgEBAA==\0"
#define TEST_1024_NOPOP "MIID/DCCA2MGA4g3AjGCA1oGA4g3AwYDiDcEEioxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTISZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwE1FQYXJzZSBTRVQgYXMgMi45OTkuMiAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAGCWCGSAFlAwQCAgYJKyQDAwIIAQELMGsGA4g3ATFkE2JQYXJzZSBTRVQgYXMgMi45OTkuMSBkYXRhIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MGFiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDUxMjM0NQYHKwYBAQEBFgYHKwYBAQEBFg==\0"

#define TEST_1025_NOPOP "MIID/TCCA2QGA4g3AjGCA1sGA4g3AwYDiDcEEisxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBNRUGFyc2UgU0VUIGFzIDIuOTk5LjIgMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwBglghkgBZQMEAgIGCSskAwMCCAEBCzBrBgOINwExZBNiUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YSAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1MTIzNDUGBysGAQEBARYGBysGAQEBARY=\0"
#define TEST_1024_POP "MIIEBzCCA2MGA4g3AjGCA1oGA4g3AwYDiDcEEioxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTISZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwE1FQYXJzZSBTRVQgYXMgMi45OTkuMiAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAGCWCGSAFlAwQCAgYJKyQDAwIIAQELMGsGA4g3ATFkE2JQYXJzZSBTRVQgYXMgMi45OTkuMSBkYXRhIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MGFiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDUxMjM0NQYHKwYBAQEBFgYHKwYBAQEBFgYJKoZIhvcNAQkH\0"

#define TEST_LONG_ATTR "MIIENzCCA54GA4g3AjGCA5UGA4g3AwYDiDcEEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTATUVBhcnNlIFNFVCBhcyAyLjk5OS4yIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MAYJYIZIAWUDBAICBgkrJAMDAggBAQswawYDiDcBMWQTYlBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEgMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwYWIxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTEyMzQ1BgcrBgEBAQEWBgcrBgEBAQEW\0"

#define EST_UT_MAX_CMD_LEN 255
extern EST_CTX *ectx;

static void us895_clean (void)
{
}

static int us895_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US895_SERVER_PORT,
                  US895_SERVER_CERTKEY,
                  US895_SERVER_CERTKEY,
                  "US895 test realm",
                  US895_CACERT,
                  US895_TRUSTED_CERT,
                  "CA/estExampleCA.cnf",
                  manual_enroll,
                  0,
                  nid);

    if (rv) {
        return (rv);
    }

    /*
     * Next we start an EST proxy acting as an RA
     */
    rv = st_proxy_start(US895_PROXY_PORT,
                        US895_SERVER_CERTKEY,
                        US895_SERVER_CERTKEY,
                        "US895 test realm",
                        US895_CACERT,
                        US895_TRUSTED_CERT,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US895_SERVER_PORT,
                        0,
                        nid);

    SLEEP(1);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us895_init_suite (void)
{
    int rv = 0;
    char cmd[EST_UT_MAX_CMD_LEN];

    printf("Starting EST Server CSR attributes unit tests.\n");

    /*
     * gen the keypair to be used for EST Proxy testing
     */
    snprintf(
        cmd,
        EST_UT_MAX_CMD_LEN,
        "openssl ecparam -name prime256v1 -genkey -out %s",
        SERVER_UT_PUBKEY);
    printf("%s\n", cmd);

    rv = system(cmd);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US895_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    /*
     * start the server for the tests that need to talk to a server
     */
    us895_clean();

    /*
     * Start an instance of the EST server
     */
    rv = us895_start_server(0, 0);
    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us895_destroy_suite (void)
{
    st_stop();
    st_proxy_stop();
    SLEEP(2);
    return 0;
}

static unsigned char * handle_short_csrattrs_request (int *csr_len,
                                                      char *path_seg,
                                                      X509 *peer_cert,
                                                      void *app_data)
{
    unsigned char *csr_data;

    *csr_len = strlen(TEST_ATTR7);
    csr_data = malloc(*csr_len + 1);
    strncpy((char *) csr_data, TEST_ATTR7, *csr_len);
    csr_data[*csr_len] = 0;
    return (csr_data);
}

static unsigned char * handle_corrupt_csrattrs_request (int *csr_len,
                                                        char *path_seg,
                                                        X509 *peer_cert,
                                                        void *app_data)
{
    unsigned char *csr_data;

    *csr_len = strlen(TEST_ATTR8);
    csr_data = malloc(*csr_len + 1);
    strncpy((char *) csr_data, TEST_ATTR8, *csr_len);
    csr_data[*csr_len] = 0;
    return (csr_data);
}

static unsigned char * handle_long_csrattrs_request (int *csr_len,
                                                     char *path_seg,
                                                     X509 *peer_cert,
                                                     void *app_data)
{
    unsigned char *csr_data;

    *csr_len = strlen(TEST_LONG_ATTR);
    csr_data = malloc(*csr_len + 1);
    strncpy((char *) csr_data, TEST_LONG_ATTR, *csr_len);
    csr_data[*csr_len] = 0;
    return (csr_data);
}

static unsigned char * handle_correct_csrattrs_request (int *csr_len,
                                                        char * path_seg,
                                                        X509 *peer_cert,
                                                        void *app_data)
{
    unsigned char *csr_data;

    *csr_len = strlen(TEST_ATTR1);
    csr_data = malloc(*csr_len + 1);
    strncpy((char *) csr_data, TEST_ATTR1, *csr_len);
    csr_data[*csr_len] = 0;
    return (csr_data);
}

static unsigned char * handle_nopop_csrattrs_request (int *csr_len,
                                                      char *path_seg,
                                                      X509 *peer_cert,
                                                      void *app_data)
{
    unsigned char *csr_data;

    *csr_len = strlen(TEST_ATTR_NOPOP);
    csr_data = malloc(*csr_len + 1);
    strncpy((char *) csr_data, TEST_ATTR_NOPOP, *csr_len);
    csr_data[*csr_len] = 0;
    return (csr_data);
}

static unsigned char * handle_empty_csrattrs_request (int *csr_len,
                                                      char *path_seg,
                                                      X509 *peer_cert,
                                                      void *app_data)
{
    unsigned char *csr_data;

    *csr_len = 0;
    csr_data = NULL;
    return (csr_data);
}

/*
 * Callback function passed to est_proxy_init()
 */
static int proxy_manual_cert_verify (X509 *cur_cert, int openssl_cert_error)
{
    BIO * bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    int approve = 0;
    const ASN1_BIT_STRING *cur_cert_sig;
    const X509_ALGOR *cur_cert_sig_alg;
    

    /*
     * Print out the specifics of this cert
     */
    printf(
        "%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
        __FUNCTION__,
        openssl_cert_error,
        X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);
    /*
     * Next call prints out the signature which can be used as the fingerprint
     * This fingerprint can be checked against the anticipated value to determine
     * whether or not the server's cert should be approved.
     */
#ifdef HAVE_OLD_OPENSSL    
    X509_get0_signature((ASN1_BIT_STRING **)&cur_cert_sig,
                        (X509_ALGOR **)&cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, (X509_ALGOR *)cur_cert_sig_alg,
                         (ASN1_BIT_STRING *)cur_cert_sig);
#else    
    X509_get0_signature(&cur_cert_sig, &cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, cur_cert_sig_alg, cur_cert_sig);
#endif    

    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        approve = 1;
    }

    BIO_free(bio_err);

    return approve;
}

/*
 * Test1 - exercise the server side variations triggered
 *         by est_client_get_csrattrs()
 */
static void us895_test1 (void)
{
    EST_CTX *ctx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY * priv_key;
    int csr_len;
    unsigned char *csr_data = NULL;

    SLEEP(1);

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(SERVER_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(SERVER_UT_PUBKEY);
    if (priv_key == NULL) {
        printf("\nError while reading private key file %s\n", SERVER_UT_PUBKEY);
        return;
    }

    ctx = est_client_init(
        cacerts,
        cacerts_len,
        EST_CERT_FORMAT_PEM,
        proxy_manual_cert_verify);
    CU_ASSERT(ctx != NULL);

    rc = est_client_set_auth(ctx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ctx, US895_SERVER_IP, US895_PROXY_PORT, NULL);

    /* clear callback */
    if (est_set_csr_cb(ectx, NULL)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }

    /* clear csrattrs */
    rc = est_server_init_csrattrs(ectx, NULL, 0);
    CU_ASSERT(rc == EST_ERR_NONE);
    /* should get 204 with no data */
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_HTTP_NO_CONTENT);
    CU_ASSERT(csr_len == 0);
    CU_ASSERT(csr_data == NULL);

    /* Real base64 string - should pass */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR_POP, strlen(TEST_ATTR_POP));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR_POP));
    CU_ASSERT(strncmp(TEST_ATTR_POP, (const char *) csr_data, csr_len) == 0);

    if (est_set_csr_cb(ectx, &handle_short_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }
    /* callback should supersede init csrattrs */
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_UNKNOWN);
    CU_ASSERT(csr_len == 0);

    if (est_set_csr_cb(ectx, &handle_corrupt_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }
    /* callback should supersede init csrattrs */
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_UNKNOWN);
    CU_ASSERT(csr_len == 0);

    if (est_set_csr_cb(ectx, &handle_long_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }
    /* callback should supersede init csrattrs */
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_UNKNOWN);
    CU_ASSERT(csr_len == 0);

    if (est_set_csr_cb(ectx, &handle_correct_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }
    /* callback should supersede init csrattrs */
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR1));
    CU_ASSERT(strncmp(TEST_ATTR1, (const char *) csr_data, csr_len) == 0);

    /* clear csrattrs */
    rc = est_server_init_csrattrs(ectx, NULL, 0);
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR1));
    CU_ASSERT(strncmp(TEST_ATTR1, (const char *) csr_data, csr_len) == 0);

    /* clear callback */
    if (est_set_csr_cb(ectx, NULL)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }

    /* Setting the smallest base64 size */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR2, strlen(TEST_ATTR2));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR2));
    CU_ASSERT(strncmp(TEST_ATTR2, (const char *) csr_data, csr_len) == 0);

    rc = est_server_init_csrattrs(ectx, TEST_ATTR3, strlen(TEST_ATTR3));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR3));
    CU_ASSERT(strncmp(TEST_ATTR3, (const char *) csr_data, csr_len) == 0);

    /* clear csrattrs */
    rc = est_server_init_csrattrs(ectx, NULL, 0);
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_HTTP_NO_CONTENT);
    CU_ASSERT(csr_len == 0);

    rc = est_server_init_csrattrs(
        ectx,
        TEST_1024_NOPOP,
        strlen(TEST_1024_NOPOP));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_1024_NOPOP));
    CU_ASSERT(strncmp(TEST_1024_NOPOP, (const char *) csr_data, csr_len) == 0);

    /* Enable PoP and test responses with PoP added */
    st_enable_pop();

    rc = est_server_init_csrattrs(ectx, TEST_ATTR_POP, strlen(TEST_ATTR_POP));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_data != NULL);
    CU_ASSERT(csr_len == 20);
    CU_ASSERT(strncmp(TEST_ATTR_POP, (const char *) csr_data, csr_len) == 0);

    rc = est_server_init_csrattrs(
        ectx,
        TEST_1024_NOPOP,
        strlen(TEST_1024_NOPOP));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_1024_POP));
    CU_ASSERT(strncmp(TEST_1024_POP, (const char *) csr_data, csr_len) == 0);

    /* Setting the size 122 */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR4_122, strlen(TEST_ATTR4_122));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR4_122POP));
    CU_ASSERT(
        strncmp(TEST_ATTR4_122POP, (const char *) csr_data, csr_len) == 0);

    /* Setting the size 117 */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR5_117, strlen(TEST_ATTR5_117));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR5_117POP));
    CU_ASSERT(
        strncmp(TEST_ATTR5_117POP, (const char *) csr_data, csr_len) == 0);

    /* Real base64 string needs PoP added - should pass */
    rc = est_server_init_csrattrs(
        ectx,
        TEST_ATTR_NOPOP,
        strlen(TEST_ATTR_NOPOP));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR_NOPOPPOP));
    CU_ASSERT(
        strncmp(TEST_ATTR_NOPOPPOP, (const char *) csr_data, csr_len) == 0);

    /* Not a real base64 string - should fail */
    rc = est_server_init_csrattrs(ectx, "US900 test1", 11);
    CU_ASSERT(rc != EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR_POP));
    CU_ASSERT(strncmp(TEST_ATTR_POP, (const char *) csr_data, csr_len) == 0);

    /* Setting the smallest size */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR2, strlen(TEST_ATTR2));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR2_POP));
    CU_ASSERT(strncmp(TEST_ATTR2_POP, (const char *) csr_data, csr_len) == 0);

    /* Setting the size 116 */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR6_116, strlen(TEST_ATTR6_116));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);

    /* Setting the size 244 */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR_244, strlen(TEST_ATTR_244));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);

    /* Setting the size 245 */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR_245, strlen(TEST_ATTR_245));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);

    /* Setting the size 250 */
    rc = est_server_init_csrattrs(ectx, TEST_ATTR_250, strlen(TEST_ATTR_250));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR_250POP));
    CU_ASSERT(strncmp(TEST_ATTR_250POP, (const char *) csr_data, csr_len) == 0);

    if (est_set_csr_cb(ectx, &handle_correct_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR1));
    CU_ASSERT(strncmp(TEST_ATTR1, (const char *) csr_data, csr_len) == 0);

    if (est_set_csr_cb(ectx, &handle_nopop_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR_NOPOPPOP));
    CU_ASSERT(
        strncmp(TEST_ATTR_NOPOPPOP, (const char *) csr_data, csr_len) == 0);

    if (est_set_csr_cb(ectx, &handle_empty_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR2_POP));
    CU_ASSERT(strncmp(TEST_ATTR2_POP, (const char *) csr_data, csr_len) == 0);

    /* disable PoP */
    st_disable_pop();

    /* clear callback */
    if (est_set_csr_cb(ectx, NULL)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }

    /* Real base64 string PoP should not be added - should pass */
    rc = est_server_init_csrattrs(
        ectx,
        TEST_ATTR_NOPOP,
        strlen(TEST_ATTR_NOPOP));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ATTR_NOPOP));
    CU_ASSERT(strncmp(TEST_ATTR_NOPOP, (const char *) csr_data, csr_len) == 0);

    /* All ASN.1 types supported by CiscoSSL */
    rc = est_server_init_csrattrs(ectx, TEST_ALL_ATTR, strlen(TEST_ALL_ATTR));
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(csr_len == strlen(TEST_ALL_ATTR));
    CU_ASSERT(strncmp(TEST_ALL_ATTR, (const char *) csr_data, csr_len) == 0);

    if (ctx) {
        est_destroy(ctx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us895_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us895_proxy_csrattrs",
            us895_init_suite,
            us895_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "CSR Proxy Attributes API1", us895_test1)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

