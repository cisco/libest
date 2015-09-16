/*------------------------------------------------------------------
 * runtest.c - Controller for all the unit testing 
 *
 * June, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 *------------------------------------------------------------------
 */

// 2015-08-11 simplified invocation of test suites, making them easier to manage
// 2015-08-11 added clear delimiters between test cases making output more readable
// 2015-08-11 improved log output with prefix differentiating client/server/proxy

#include <est.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <pthread.h>
#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#include "CUnit/Console.h"
#endif


/*
 * We're using OpenSSL, both as the CA and libest
 * requires it.  OpenSSL requires these platform specific
 * locking callbacks to be set when multi-threaded support
 * is needed.  
 */
static pthread_mutex_t *ssl_mutexes;
static void ssl_locking_callback (int mode, int mutex_num, const char *file,
                                  int line)
{
    line = 0;    // Unused
    file = NULL; // Unused

    if (mode & CRYPTO_LOCK) {
        (void)pthread_mutex_lock(&ssl_mutexes[mutex_num]);
    } else {
        (void)pthread_mutex_unlock(&ssl_mutexes[mutex_num]);
    }
}
static unsigned long ssl_id_callback (void)
{
#ifndef _WIN32
    return (unsigned long)pthread_self();
#else
    return (unsigned long)pthread_self().p;
#endif
}

void test_start(const CU_pTest pTest, const CU_pSuite pSuite)
{
    static char *suitename = NULL;

    if (pSuite->pName != suitename) {
	suitename = pSuite->pName;
	fprintf(stderr, "\n");
	fprintf(stderr,
		"********************************************************************************\n");
	fprintf(stderr,
		"********************************************************************************\n"
		"\n"
		"Suite %s\n",
		suitename);
    }
    fprintf(stderr, "\n"
	    "********************************************************************************\n"
	    "\n");
    fprintf(stderr, "Test %s ...", pTest->pName);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void print_failures(CU_pFailureRecord p)
{
    while (p != NULL) {
	fprintf(stderr,
		"\n%s:%d failed: %s\n",
		p->strFileName,
		p->uiLineNumber,
		p->strCondition);
	p = p->pNext;
    }
}

void test_complete(const CU_pTest pTest, const CU_pSuite pSuite, const CU_pFailureRecord pFailure)
{
    fprintf(stderr, "\n");
    if (pFailure == NULL) {
	fprintf(stderr, "passed\n");
    }
    else {
	print_failures(pFailure);
	// CU_basic_show_failures(CU_get_failure_list()); exit(0);
	fprintf(stderr, "\n"
		"################################################################################\n"
		"\n");
    }
    fflush(stderr);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int main(int argc, char *argv[])
{
#ifdef HAVE_CUNIT
    int xml = 0;
    int con = 0;
    CU_pFailureRecord fr;
    int size;
    int i;
    int rv;

    if (argc >= 2 && !strcmp(argv[1], "-xml")) {
	xml = 1;
    } else 
    if (argc >= 2 && !strcmp(argv[1], "-con")) {
	con = 1;
    }

    est_apps_startup();
    est_set_log_source(EST_CLIENT);

    /*
     * Install thread locking mechanism for OpenSSL
     */
    size = sizeof(pthread_mutex_t) * CRYPTO_num_locks();
    if ((ssl_mutexes = (pthread_mutex_t*)malloc((size_t)size)) == NULL) {
        printf("Cannot allocate mutexes");
	exit(1);
    }

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&ssl_mutexes[i], NULL);
    }
    CRYPTO_set_locking_callback(&ssl_locking_callback);
    CRYPTO_set_id_callback(&ssl_id_callback);
    

    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry()) {
	return CU_get_error();
    }

    #define ADD(N) { extern int N##_add_suite(void); rv = N##_add_suite(); \
	    if (rv != CUE_SUCCESS) { fprintf(stderr, "Failed "#N"_add_suite (%d)\n", rv); exit(1); } }
    ADD(us748);
    ADD(us893);
    ADD(us894);
    ADD(us895);
    ADD(us896);
    ADD(us897);
    ADD(us898);
    ADD(us899);
    ADD(us900);
    ADD(us901);
    ADD(us902);
    ADD(us903);
    ADD(us1005);
    ADD(us1060);
    ADD(us1159);
    ADD(us1864);
    ADD(us1883);
    ADD(us1884);
    ADD(us2174);

    if (xml) {
	/* Run all test using automated interface, which
	 * generates XML output */
	CU_list_tests_to_file();
	CU_automated_run_tests();
    } else if (con) {
	CU_console_run_tests();
    } else {
	/* Run all tests using the CUnit Basic interface,
	 * which generates text output */
#if 0
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
#else
	CU_set_test_start_handler   (test_start);
	CU_set_test_complete_handler(test_complete);
	CU_run_all_tests();
#endif
	fr = CU_get_failure_list();
	if (fr) {
	    fprintf(stderr, "\nHere is a summary of the failed test cases:\n");
	    print_failures(fr);
	} else {
	    fprintf(stderr, "\nAll enabled tests passed.\n");
	}
    }

    /*
     * Tear down the mutexes used by OpenSSL
     */
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&ssl_mutexes[i]);
    }
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    free(ssl_mutexes);
    
    CU_cleanup_registry();
    est_apps_shutdown();

    return CU_get_error();
#else
    printf("\nlibcunit not installed, unit tests are not enabled\n");
    return 255;
#endif
}
