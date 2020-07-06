/*------------------------------------------------------------------
 * us5418.c - Unit Tests for User Story 5418 - Performance Timers
 *
 * September, 2019
 *
 * Copyright (c) 2019 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include "us5418.h"

#ifndef WIN32
#define US5418_COAP_CLIENT_EMU_PATH "../util/"
#else
#define US5418_COAP_CLIENT_EMU_PATH "..\\util\\"
#endif
#define US5418_COAP_CLIENT_EMU "est_coap_client.py"

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;
extern EST_CTX *ectx;
static char temp_dir[MAX_FILENAME_LEN + 1];
static FILE *fh;
static const char *request_type_str[] = {
    FOREACH_REQUESTS(GENERATE_STRING)
    "MAX_REQ"
};
static pid_t pid;

/*
 * Used to test the CoAP init API function
 */
#define US5418_LIBCOAP_API_TEST_PORT 29002

/*
 * If this test suite fails seemingly randomly, blocking could be
 * the cause as the number of lines are dependent on the blocking used for the
 * requests
 */
/* No auth cb since Enhanced Cert Auth is off. Auth succeeds with cert auth */
#define US5418C_SIMPLE_ENROLL_LINE_COUNT HEADER_LINE_COUNT + 16
#define US5418C_GET_CACERTS_LINE_COUNT HEADER_LINE_COUNT + 12
#define US5418C_CSR_ATTRS_LINE_COUNT HEADER_LINE_COUNT + 12
#define US5418C_SERVER_KEYGEN_LINE_COUNT HEADER_LINE_COUNT + 23
#define US5418C_SIMPLE_REENROLL_LINE_COUNT HEADER_LINE_COUNT + 16

static void us5418c_clean (void) {}

static int us5418c_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_coap(US5418_SERVER_PORT, US5418_SERVER_CERT_AND_KEY,
                       US5418_SERVER_CERT_AND_KEY, "US5418 test realm",
                       US5418_CACERTS, US5418_TRUSTED_CERT,
                       US5418_OPENSSL_CNF, manual_enroll, 0, nid);
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
static int us5418c_init_suite (void)
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

    us5418c_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5418c_start_server(0, 0);

    /* Build out temp directory */
#ifdef WIN32
    snprintf(temp_dir, MAX_FILENAME_LEN, "%s\\", getenv("TEMP"));
#else
    snprintf(temp_dir, MAX_FILENAME_LEN, "/tmp/");
#endif

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    pid = getpid();

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5418c_destroy_suite (void)
{
    st_stop();
    free(cacerts);
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
static void us5418c_logger_file (char *format, va_list l)
{
    vfprintf(fh, format, l);
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
static void us5418c_test1 (void)
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

static int get_num_entries (REQUESTS request_type)
{
    switch (request_type) {
    case SIMPLE_ENROLL:
        return US5418C_SIMPLE_ENROLL_LINE_COUNT;
    case GET_CACERTS:
        return US5418C_GET_CACERTS_LINE_COUNT;
    case CSR_ATTRS:
        return US5418C_CSR_ATTRS_LINE_COUNT;
    case SERVER_KEYGEN:
        return US5418C_SERVER_KEYGEN_LINE_COUNT;
    case SIMPLE_REENROLL:
        return US5418C_SIMPLE_REENROLL_LINE_COUNT;
    default:
        return -1;
    }
}

/*
 * This test contains the logic for testing the logging of timers for all the
 * different forms of requests. Simply enter in the type of request as a
 * parameter and use the returned boolean value to determine if the test
 * succeeded (1 success, 0 failure) for logging purposes The request type
 * strings are the following:
 * - "SIMPLE_ENROLL"
 * - "GET_CACERTS"
 * - "CSR_ATTRS"
 * - "SERVER_KEYGEN"
 * - "SIMPLE_REENROLL"
 */
static char perform_timer_logging_test (REQUESTS request_type)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];
    char coap_server_logs[MAX_FILENAME_LEN];
    char csv_filename[MAX_FILENAME_LEN];
    FILE *fh_csv;
    char c;
    int exit_code = 0;
    int line_count = 0;
    EST_ERROR est_err = EST_ERR_UNKNOWN;
    char success = 1;
    st_stop();
    us5418c_start_server(0, 0);
    CU_ASSERT_5418(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5418_CSSL_NOT_SET_MSG);
        CU_FAIL_5418(US5418_CSSL_NOT_SET_MSG);
        goto end;
    }

    snprintf(coap_server_logs, MAX_FILENAME_LEN, "%sus5418c_estserver_%ld.log",
             temp_dir, (unsigned long)pid);
    if (strnlen(coap_server_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL_5418("The logfile for the est server was too long. Add "
                     "symbolic links to make paths shorter.");
        goto end;
    }

    if ((fh = fopen(coap_server_logs, "w")) == NULL) {
        CU_FAIL_5418("Could not open server log file");
        goto end;
    }

    est_err = est_init_logger(EST_LOG_LVL_INFO, us5418c_logger_file);
    if (est_err != EST_ERR_NONE) {
        CU_FAIL_5418("Couldn't init the libest logger");
        goto end;
    }

    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5418c_estclient_%ld.log",
             temp_dir, (unsigned long)pid);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL_5418("The logfile for the est_coap_client.py emulator was too "
                     "long. Add symbolic links to make paths shorter.");
        goto end;
    }
    est_err = est_enable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "%s --port %d --debug --cert %s --key %s --cacert %s "
             "2>&1 | tee %s",
             cssl_emulator_path, cssl_emulator_path,
             US5418_COAP_CLIENT_EMU_PATH, US5418_COAP_CLIENT_EMU,
             REQUESTS_TO_STR(request_type), US5418_SERVER_PORT,
             US5418_CLIENT_CERTKEY, US5418_CLIENT_CERTKEY,
             US5418_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_UT_MAX_CMD_LEN) >= EST_UT_MAX_CMD_LEN) {
        CU_FAIL_5418(
            "Commmand for executing the est_coap_client.py emulator was too "
            "long. Add symbolic links to make paths shorter.");
        goto end;
    }
    exit_code = system(cmd);
    CU_ASSERT_5418(!exit_code);
    est_err = est_disable_performance_timers(ectx);
    CU_ASSERT_5418(est_err == EST_ERR_NONE);
    est_err = est_init_logger(EST_LOG_LVL_INFO, NULL);
    if (est_err != EST_ERR_NONE) {
        CU_FAIL_5418("Couldn't reset the libest logger");
        goto end;
    }
    fclose(fh);
    snprintf(csv_filename, MAX_FILENAME_LEN, "%sus5418c_timer_%ld.csv",
             temp_dir, (unsigned long)pid);
    if (strnlen(csv_filename, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL_5418("The path of the output csv for the est timers is "
                     "too long. Add symbolic links to make paths shorter.");
        goto end;
    }
    snprintf(cmd, EST_UT_MAX_CMD_LEN, "LD_LIBRARY_PATH=%s/lib python %s %s %s",
             cssl_emulator_path, PARSE_TIMER_PATH, coap_server_logs,
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
    remove(coap_server_logs);
    remove(coap_client_logs);
    remove(csv_filename);

    CU_ASSERT_5418(line_count == get_num_entries(request_type));
end:
    return (success);
}

/*
 * Test Timer with Simple Enroll
 * This test checks to make sure the logging and python script for generating a
 * csv of the logged timings is working on a simple enroll request. The test
 * consists of the following steps:
 * - enable timer logging in st server and write logs to a file
 * - launch python coap client emulator
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418c_test2 (void)
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
 * - launch python coap client emulator
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418c_test3 (void)
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
 * - launch python coap client emulator
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418c_test4 (void)
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
 * - launch python coap client emulator
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418c_test5 (void)
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
 * - launch python coap client emulator
 * - disable timer logging, close logging file, and reset logging
 * - launch python csv generator and ensure it has entries
 */
static void us5418c_test6 (void)
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
int us5418c_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5418_SERVER_CERT_AND_KEY, US5418_TRUSTED_CERT,
                             US5418_CACERTS, US5418_LIBCOAP_API_TEST_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5418c_Performace_Timers_COAP", us5418c_init_suite,
                          us5418c_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL == CU_add_test(pSuite, "Test Timer Enable/Disable API",
                                 us5418c_test1))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL == CU_add_test(pSuite, "Test Timer with Simple Enroll",
                                 us5418c_test2))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL == CU_add_test(pSuite, "Test Timer with Get CA Certs",
                                 us5418c_test3))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL == CU_add_test(pSuite, "Test Timer with Get CSR Attrs",
                                 us5418c_test4))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL == CU_add_test(pSuite, "Test Timer with Server Keygen",
                                 us5418c_test5))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL == CU_add_test(pSuite, "Test Timer with Simple Re-enroll",
                                 us5418c_test6))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    return CUE_SUCCESS;
#endif
}
