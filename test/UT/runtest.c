/*------------------------------------------------------------------
 * runtest.c - Controller for all the unit testing
 *
 * June, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <est.h>
#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#include "CUnit/Console.h"
#endif
#ifndef WIN32
#include <pthread.h>
#include <signal.h>
#define DISABLE_SUITE 1
#else 
/* Used to disable suites on Windows*/
#define DISABLE_SUITE 0
#endif 
#define ENABLE_ALL_SUITES 1
/* Client specific suites */
extern int us896_add_suite(void);
extern int us897_add_suite(void);
extern int us898_add_suite(void);
extern int us899_add_suite(void);
extern int us1005_add_suite(void);
extern int us1883_add_suite(void);
extern int us1060c_add_suite(void);
extern int us3496_add_suite(void);
extern int us748_add_suite(void);
extern int us893_add_suite(void);
extern int us894_add_suite(void);
extern int us895_add_suite(void);
extern int us900_add_suite(void);
extern int us901_add_suite(void);
extern int us902_add_suite(void);
extern int us903_add_suite(void);
extern int us1159_add_suite(void);
extern int us1190_add_suite(void);
extern int us1864_add_suite(void);
extern int us1884_add_suite(void);
extern int us2174_add_suite(void);
extern int us3512_add_suite(void);
extern int us3612_add_suite(void);
extern int us4020_add_suite(void);
#if (DISABLE_SUITE != 0)
extern int us1060_add_suite(void);
#endif

/*
 * Abstract OpenSSL threading platfrom callbacks
 */
#ifdef WIN32
#define MUTEX_TYPE            HANDLE
#define MUTEX_SETUP(x)        (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x)      CloseHandle(x)
#define MUTEX_LOCK(x)         WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x)       ReleaseMutex(x)
#define THREAD_ID             GetCurrentThreadId()
#else
#define MUTEX_TYPE            pthread_mutex_t
#define MUTEX_SETUP(x)        pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x)      pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)         pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)       pthread_mutex_unlock(&(x))
#define THREAD_ID             pthread_self()
#endif

/*
 * We're using OpenSSL, both as the CA and libest
 * requires it.  OpenSSL requires these platform specific
 * locking callbacks to be set when multi-threaded support
 * is needed.
 */
static MUTEX_TYPE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char * file, int line) {
    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(mutex_buf[n]);
    else
        MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void) {
    return ((unsigned long) THREAD_ID);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int main(int argc, char *argv[]) {
    int xml = 0;
    int con = 0;
    CU_pFailureRecord fr;
    int i;

    if (argc >= 2 && !strcmp(argv[1], "-xml")) {
        xml = 1;
    } else if (argc >= 2 && !strcmp(argv[1], "-con")) {
        con = 1;
    }
#ifdef HAVE_CUNIT
    int rv;

#ifndef WIN32
    struct sigaction sig_act;
    /*
     * Indicate that the broken pipe signal during writes should be
     * ignored
     */
    memset(&sig_act, 0, sizeof(struct sigaction));
    sig_act.sa_handler = SIG_IGN;
    sigemptyset(&sig_act.sa_mask);
    if (sigaction(SIGPIPE, &sig_act, NULL) == -1) {
        printf("\nCannot set ignore action for SIGPIPE\n");
    }
#endif 

    est_apps_startup();

    /*
     * Install thread locking mechanism for OpenSSL
     */
    mutex_buf = malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
    if (!mutex_buf) {
        printf("Cannot allocate mutexes");
        exit(1);
    }
    for (i = 0; i < CRYPTO_num_locks(); i++)
    MUTEX_SETUP(mutex_buf[i]);
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);

    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }
#ifdef ENABLE_ALL_SUITES
    rv = us748_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US748 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us893_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US893 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us894_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US894 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us895_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US895 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us896_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US896 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us897_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US897 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us898_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US898 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us899_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US899 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us900_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US900 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us901_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US901 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us902_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US902 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us903_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US903 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us1005_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1005 (%d)", rv);
        exit(1);
    }
#endif
#if (DISABLE_SUITE != 0)
    rv = us1060_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1060 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us1060c_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1060c (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES 
    rv = us1159_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1159 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us1190_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1190 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us1864_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1864 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us1883_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1883 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us1884_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US1884 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us2174_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US2174 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us3496_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US3496 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us3512_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US3512 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us3612_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US3612 (%d)", rv);
        exit(1);
    }
#endif
#ifdef ENABLE_ALL_SUITES
    rv = us4020_add_suite();
    if (rv != CUE_SUCCESS) {
        printf("\nFailed to add test suite for US4020 (%d)", rv);
        exit(1);
    }
#endif

    if (xml) {
        /* Run all test using automated interface, which
         * generates XML output */
        CU_list_tests_to_file();
        CU_automated_run_tests();
    }
    else if (con) {
        CU_console_run_tests();
    }
    else {
        /* Run all tests using the CUnit Basic interface,
         * which generates text output */
        CU_basic_set_mode(CU_BRM_VERBOSE);
        CU_basic_run_tests();
        fr = CU_get_failure_list();
        if (fr) {
            printf("\n\nHere is a summary of the failed test cases:\n");
            CU_basic_show_failures(fr);
        }
    }

    /*
     * Tear down the mutexes used by OpenSSL
     */
    if (!mutex_buf)
    return 0;
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
    MUTEX_CLEANUP(mutex_buf[i]);
    free(mutex_buf);
    mutex_buf = NULL;

    CU_cleanup_registry();
    est_apps_shutdown();

    return CU_get_error();
#else
    printf("\nlibcunit not installed, unit test are not enabled\n");
#endif
}


