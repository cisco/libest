/*------------------------------------------------------------------
 * us5418h.c - Unit Tests for User Story 5418 - Performance Timers
 *
 * September, 2019
 *
 * Copyright (c) 2019 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include "us5418.h"
#include <pthread.h>

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

static char *cssl_emulator_path = NULL;

extern EST_CTX *ectx;
static char temp_dir[MAX_FILENAME_LEN + 1];
static FILE *fh;
static EVP_PKEY *client_pkey = NULL;
static X509 *client_cert = NULL;
static unsigned char *ca_chain_bytes;
static int ca_chain_bytes_len = 0;
pthread_mutex_t lock;
static pid_t pid;

/* Auth fails on first req */
#define US5418H_SIMPLE_ENROLL_LINE_COUNT HEADER_LINE_COUNT + 14
#define US5418H_GET_CACERTS_LINE_COUNT HEADER_LINE_COUNT + 3
#define US5418H_CSR_ATTRS_LINE_COUNT HEADER_LINE_COUNT + 3
#define US5418H_SERVER_KEYGEN_LINE_COUNT HEADER_LINE_COUNT + 15
#define US5418H_SIMPLE_REENROLL_LINE_COUNT HEADER_LINE_COUNT + 14

typedef EST_ERROR (*setup_cb_t) (EST_CTX **ctx);

static void us5418h_clean (void) {}

static int us5418h_start_server (int manual_enroll, int nid)
{
    int rv;
    if (pthread_mutex_init(&lock, NULL) != 0) 
    { 
        printf("\n mutex init has failed\n"); 
        return 1; 
    } 
    rv = st_start(US5418_SERVER_PORT, US5418_SERVER_CERT_AND_KEY,
                  US5418_SERVER_CERT_AND_KEY, "US5418 test realm",
                  US5418_CACERTS, US5418_TRUSTED_CERT, US5418_OPENSSL_CNF,
                  manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
    }

    st_set_default_est_event_callbacks();

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5418h_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5418_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us5418h_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5418h_start_server(0, 0);
    if (rv) {
        printf("The st server for US5418 could not be started.\n");
        return rv;
    }
    /* Build out temp directory */
#ifdef WIN32
    snprintf(temp_dir, MAX_FILENAME_LEN, "%s\\", getenv("TEMP"));
#else
    snprintf(temp_dir, MAX_FILENAME_LEN, "/tmp/");
#endif
    /* Need this since python now depends upon ciscossl */
    cssl_emulator_path = getenv("COAP_EMU_SSL");

    read_x509_cert_and_key_file(US5418_CLIENT_CERTKEY, US5418_CLIENT_CERTKEY,
                                &client_cert, &client_pkey);

    ca_chain_bytes_len = read_binary_file(US5418_CACERTS, &ca_chain_bytes);
    if (ca_chain_bytes_len <= 0) {
        printf("The ca chain file could not be read or had zero len.\n");
        return 1;
    }
    pid = getpid();

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5418h_destroy_suite (void)
{
    st_stop();
    if (client_pkey) {
        EVP_PKEY_free(client_pkey);
    }
    if (ca_chain_bytes) {
        free(ca_chain_bytes);
    }
    if (client_cert) {
        X509_free(client_cert);
    }
    if (cacerts) {
        free(cacerts);
    }
    printf("Finishing up. Destroying Suite US5418\n");
    return 0;
}

/*
 * This is a simple callback used to override the default
 * logging facility in libest.
 * Used to test the logging API's.
 *
 * These are the log levels defined in libest/src/est.h
 * EST_LOG_LVL_ERR = 1,
 * EST_LOG_LVL_WARN,
 * EST_LOG_LVL_INFO
 */
static void us5418h_logger_file (char *format, va_list l)
{
    pthread_mutex_lock(&lock); 
    vfprintf(fh, format, l);
    fflush(fh);
    pthread_mutex_unlock(&lock); 
}

/*
 * Test Timer Enable/Disable API
 * Test the enable and disable perf timers API functions
 * Tests:
 * - Enable with a NULL ctx (should fail)
 * - Enable with st_server ctx (should pass)
 * - Enable with st_server ctx again (should pass)
 * - Disable with st_server ctx (should pass)
 * - Disable with st_server ctx again (should pass)
 * - Disable with a NULL ctx (should fail)
 */
static void us5418h_test1 (void)
{
    PRINT_START;
    EST_ERROR est_err = EST_ERR_UNKNOWN;
    est_err = est_enable_performance_timers(NULL);
    CU_ASSERT_5418(est_err == EST_ERR_NO_CTX);
    est_err = est_enable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    est_err = est_enable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    est_err = est_disable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    est_err = est_disable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    est_err = est_disable_performance_timers(NULL);
    CU_ASSERT_5418(est_err == EST_ERR_NO_CTX);
    PRINT_END;
}

EST_ERROR setup_client_ctx(EST_CTX **cctx) {
    EST_ERROR est_err;
    *cctx = est_client_init(ca_chain_bytes, ca_chain_bytes_len,
                           EST_CERT_FORMAT_PEM, NULL);
    if (!(*cctx)) {
        /* No success variable in here so can't use CU_FAIL_5418 */
        printf("The client context was not properly initialized.\n");
        CU_FAIL("The client context was not properly initialized.");
        return EST_ERR_NO_CTX;
    }
    est_err = est_client_set_server(*cctx, US5418_SERVER_IP, US5418_SERVER_PORT, NULL);
    if (est_err != EST_ERR_NONE) {
        printf("EST_ERROR %s occured while setting the server in the est client context\n",
               EST_ERR_NUM_TO_STR(est_err));
        CU_FAIL("EST error occured while setting the server in the est client context");
        return est_err;
    }
    est_err = est_client_set_auth(*cctx, "estuser", "estpwd", client_cert, client_pkey);
    if (est_err != EST_ERR_NONE) {
        printf("EST_ERROR %s occured while setting the auth in the est client context\n",
               EST_ERR_NUM_TO_STR(est_err));
        CU_FAIL("EST error occured while setting the auth in the est client context");
        return est_err;
    }
    return EST_ERR_NONE;
}

static int get_num_entries (REQUESTS request_type)
{
    switch (request_type) {
    case SIMPLE_ENROLL:
        return US5418H_SIMPLE_ENROLL_LINE_COUNT;
    case GET_CACERTS:
        return US5418H_GET_CACERTS_LINE_COUNT;
    case CSR_ATTRS:
        return US5418H_CSR_ATTRS_LINE_COUNT;
    case SERVER_KEYGEN:
        return US5418H_SERVER_KEYGEN_LINE_COUNT;
    case SIMPLE_REENROLL:
        return US5418H_SIMPLE_REENROLL_LINE_COUNT;
    default:
        return -1;
    }
}

static EST_ERROR perform_est_request (REQUESTS request_type, EVP_PKEY *pkey,
                                      X509 *reenroll_cert, setup_cb_t setup_cb)
{
    EST_CTX *cctx = NULL;
    EST_ERROR est_err;
    int pkcs7_len = 0;
    int cacerts_len = 0;
    unsigned char *csr_attrs_buf;
    int csr_attrs_len = 0;
    int newkey_len = 0;

    est_err = setup_cb(&cctx);
    if (est_err != EST_ERR_NONE) {
        /* No success variable in here so can't use CU_FAIL_5418 */
        printf("EST_ERROR %s occured during setup of client context\n",
               EST_ERR_NUM_TO_STR(est_err));
        CU_FAIL("EST error occured during setup of client context");
        if (cctx) {
            est_destroy(cctx);
        }
        return est_err;
    }
    switch (request_type) {
    case SIMPLE_ENROLL:
        est_err = est_client_enroll(cctx, "testcert", &pkcs7_len, pkey);
        if (est_err != EST_ERR_NONE) {
            printf("EST_ERROR %s occured during enrollment request\n",
                   EST_ERR_NUM_TO_STR(est_err));
            CU_FAIL("EST error occured during enrollment request");
        }
        break;
    case GET_CACERTS:
        est_err = est_client_get_cacerts(cctx, &cacerts_len);
        if (est_err != EST_ERR_NONE) {
            printf("EST_ERROR %s occured during get cacerts request\n",
                   EST_ERR_NUM_TO_STR(est_err));
            CU_FAIL("EST error occured during get cacerts request");
        }
        break;
    case CSR_ATTRS:
        est_err = est_client_get_csrattrs(cctx, &csr_attrs_buf, &csr_attrs_len);
        if (est_err != EST_ERR_NONE) {
            printf("EST_ERROR %s occured during get csr attrs request\n",
                   EST_ERR_NUM_TO_STR(est_err));
            CU_FAIL("EST error occured during get csr attrs request");
        }
        break;
    case SERVER_KEYGEN:
        est_err = est_client_server_keygen_enroll(cctx, "testcert", &pkcs7_len,
                                                  &newkey_len, pkey);
        if (est_err != EST_ERR_NONE) {
            printf("EST_ERROR %s occured during get server keygen request\n",
                   EST_ERR_NUM_TO_STR(est_err));
            CU_FAIL("EST error occured during get server keygen request");
        }
        break;
    case SIMPLE_REENROLL:
        est_err = est_client_reenroll(cctx, reenroll_cert, &pkcs7_len, pkey);
        if (est_err != EST_ERR_NONE) {
            printf("EST_ERROR %s occured during reenroll request\n",
                   EST_ERR_NUM_TO_STR(est_err));
            CU_FAIL("EST error occured during reenroll request");
        }
        break;
    default:
        printf("EST_ERROR %s occured during get csr attrs request\n",
               EST_ERR_NUM_TO_STR(est_err));
        CU_FAIL("EST error occured during get csr attrs request");
        est_err = EST_ERR_INVALID_PARAMETERS;
    }
    if (cctx) {
        est_destroy(cctx);
    }
    return est_err;
}
/*
 * This test contains the logic for testing the logging of timers for all the
 * different forms of requests. Simply enter in the type of request as a
 * parameter and use the returned boolean value to determine if the test
 * succeeded (1 success, 0 failure) for logging purposes The request type
 * strings are the following:
 * - SIMPLE_ENROLL
 * - GET_CACERTS
 * - CSR_ATTRS
 * - SERVER_KEYGEN
 * - SIMPLE_REENROLL
 */
static char perform_timer_logging_test (REQUESTS request_type)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    char est_client_logs[MAX_FILENAME_LEN];
    char est_server_logs[MAX_FILENAME_LEN];
    char csv_filename[MAX_FILENAME_LEN];
    FILE *fh_csv;
    char c;
    int exit_code = 0;
    int line_count = 0;
    EST_ERROR est_err = EST_ERR_UNKNOWN;
    char success = 1;

    snprintf(est_server_logs, MAX_FILENAME_LEN, "%sus5418h_estserver_%ld.log",
             temp_dir, (unsigned long)pid);
    if (strnlen(est_server_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL_5418("The logfile for the est_coap_client.py emulator was "
                     "too long. Add symbolic links to make paths shorter.");
        goto end;
    }

    if ((fh = fopen(est_server_logs, "w")) == NULL) {
        CU_FAIL_5418("Could not open server log file");
        goto end;
    }

    pthread_mutex_lock(&lock); 
    est_err = est_init_logger(EST_LOG_LVL_INFO, us5418h_logger_file);
    pthread_mutex_unlock(&lock); 
    if (est_err != EST_ERR_NONE) {
        CU_FAIL_5418("Couldn't init the libest logger");
        goto end;
    }

    snprintf(est_client_logs, MAX_FILENAME_LEN, "%sus5418h_estclient_%ld.log",
             temp_dir, (unsigned long)pid);
    if (strnlen(est_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL_5418("The logfile for the est_coap_client.py emulator was "
                     "too long. Add symbolic links to make paths shorter.");
        goto end;
    }
    est_err = est_enable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    /* Perform EST request */
    est_err = perform_est_request(request_type, client_pkey, client_cert,
                                  (setup_cb_t)setup_client_ctx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);    
    est_err = est_disable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    /* Wait for logging lock to change the logging */

    pthread_mutex_lock(&lock); 
    est_err = est_init_logger(EST_LOG_LVL_INFO, NULL);
    pthread_mutex_unlock(&lock); 
    if (est_err != EST_ERR_NONE) {
        CU_FAIL_5418("Couldn't reset the libest logger");
        goto end;
    }
    fclose(fh);
    snprintf(csv_filename, MAX_FILENAME_LEN, "%sus5418h_timer_%ld.csv",
             temp_dir, (unsigned long)pid);
    if (strnlen(csv_filename, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL_5418("The path of the output csv for the est timers is "
                     "too long. Add symbolic links to make paths shorter.");
        goto end;
    }
    snprintf(cmd, EST_UT_MAX_CMD_LEN, "LD_LIBRARY_PATH=%s/lib python %s %s %s",
             cssl_emulator_path, PARSE_TIMER_PATH, est_server_logs,
             csv_filename);
    if (strnlen(cmd, EST_UT_MAX_CMD_LEN) >= EST_UT_MAX_CMD_LEN) {
        CU_FAIL_5418("Commmand for generating the timing csv file is too long. "
                     "Add symbolic links to make paths shorter.");
        goto end;
    }
    exit_code = system(cmd);
    CU_ASSERT_5418(!exit_code);
    // Open the file
    fh_csv = fopen(csv_filename, "r");

    // Check if file exists
    if (fh_csv == NULL) {
        printf("Could not open file %s", csv_filename);
        CU_FAIL_5418("Could not open output csv file");
        goto end;
    }

    // Extract characters from file and store in character c
    for (c = getc(fh_csv); c != EOF; c = getc(fh_csv)) {
        if (c == '\n') { // Increment count if this character is newline
            line_count += 1;
        }
    }
    // Close the file
    fclose(fh_csv);
    remove(est_server_logs);
    remove(est_client_logs);
    remove(csv_filename);
    CU_ASSERT_5418(line_count == get_num_entries(request_type));
end:
    return success;
}

/*
 * Test Timer with Simple Enroll
 * This test checks to make sure the logging and python script for generating a
 * csv of the logged timings is working on a simple enroll request. The test
 * consists of the following steps:
 * - enable timer logging in st server and write logs to a file
 * - use est client to perform request
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418h_test2 (void)
{
    /*
     * success is defined in the PRINT_START define and is used for logging
     * success or failure of the test
     */
    PRINT_START;
    success = perform_timer_logging_test(SIMPLE_ENROLL);
    PRINT_END;
}
/*
 * Test Timer with Get CA Certs
 * This test checks to make sure the logging and python script for generating a
 * csv of the logged timings is working on a simple enroll request. The test
 * consists of the following steps:
 * - enable timer logging in st server and write logs to a file
 * - use est client to perform request
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418h_test3 (void)
{
    /*
     * success is defined in the PRINT_START define and is used for logging
     * success or failure of the test
     */
    PRINT_START;
    success = perform_timer_logging_test(GET_CACERTS);
    PRINT_END;
}

/*
 * Test Timer with Get CSR Attrs
 * This test checks to make sure the logging and python script for generating a
 * csv of the logged timings is working on a simple enroll request. The test
 * consists of the following steps:
 * - enable timer logging in st server and write logs to a file
 * - use est client to perform request
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418h_test4 (void)
{
    /*
     * success is defined in the PRINT_START define and is used for logging
     * success or failure of the test
     */
    PRINT_START;
    success = perform_timer_logging_test(CSR_ATTRS);
    PRINT_END;
}

/*
 * Test Timer with Server Keygen
 * This test checks to make sure the logging and python script for generating a
 * csv of the logged timings is working on a simple enroll request. The test
 * consists of the following steps:
 * - enable timer logging in st server and write logs to a file
 * - use est client to perform request
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418h_test5 (void)
{
    /*
     * success is defined in the PRINT_START define and is used for logging
     * success or failure of the test
     */
    PRINT_START;
    success = perform_timer_logging_test(SERVER_KEYGEN);
    PRINT_END;
}

/*
 * Test Timer with Simple Re-enroll
 * This test checks to make sure the logging and python script for generating a
 * csv of the logged timings is working on a simple enroll request. The test
 * consists of the following steps:
 * - enable timer logging in st server and write logs to a file
 * - use est client to perform request
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418h_test6 (void)
{
    /*
     * success is defined in the PRINT_START define and is used for logging
     * success or failure of the test
     */
    PRINT_START;
    success = perform_timer_logging_test(SIMPLE_REENROLL);
    PRINT_END;
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5418h_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5418h_Performace_Timers_HTTP", us5418h_init_suite,
                          us5418h_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL ==
         CU_add_test(pSuite, "Test Timer Enable/Disable API", us5418h_test1))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL ==
         CU_add_test(pSuite, "Test Timer with Simple Enroll", us5418h_test2))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL ==
         CU_add_test(pSuite, "Test Timer with Get CA Certs", us5418h_test3))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL ==
         CU_add_test(pSuite, "Test Timer with Get CSR Attrs", us5418h_test4))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL ==
         CU_add_test(pSuite, "Test Timer with Server Keygen", us5418h_test5))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite, "Test Timer with Simple Re-enroll",
                             us5418h_test6))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    return CUE_SUCCESS;
#endif
}
