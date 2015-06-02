/*------------------------------------------------------------------
 * runtest.c - Controller for all the unit testing 
 *
 * June, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <est.h>
#include <pthread.h>
#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#include "CUnit/Console.h"
#endif

extern int us748_add_suite(void);
extern int us893_add_suite(void);
extern int us894_add_suite(void);
extern int us895_add_suite(void);
extern int us896_add_suite(void);
extern int us897_add_suite(void);
extern int us898_add_suite(void);
extern int us899_add_suite(void);
extern int us900_add_suite(void);
extern int us901_add_suite(void);
extern int us902_add_suite(void);
extern int us903_add_suite(void);
extern int us1005_add_suite(void);
extern int us1060_add_suite(void);
extern int us1159_add_suite(void);
extern int us1864_add_suite(void);
extern int us1883_add_suite(void);
extern int us1884_add_suite(void);
extern int us2174_add_suite(void);


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
    return (unsigned long)pthread_self();
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int main(int argc, char *argv[])
{
    int xml = 0;
    int con = 0;
    CU_pFailureRecord fr;
    int size;
    int i;

    if (argc >= 2 && !strcmp(argv[1], "-xml")) {
	xml = 1;
    } else 
    if (argc >= 2 && !strcmp(argv[1], "-con")) {
	con = 1;
    }
#ifdef HAVE_CUNIT
    int rv;

    est_apps_startup();

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
#if 10
    rv = us748_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US748 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us893_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US893 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us894_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US894 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us895_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US895 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us896_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US896 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us897_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US897 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us898_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US898 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us899_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US899 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us900_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US900 (%d)", rv);
	exit(1);
    }
#endif
#if 10
    rv = us901_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US901 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us902_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US902 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us903_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US903 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us1005_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US1005 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us1060_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US1060 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us1159_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US1159 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us1864_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US1864 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us1883_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US1883 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us1884_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US1884 (%d)", rv);
	exit(1);
    }
#endif
#if 10 
    rv = us2174_add_suite();
    if (rv != CUE_SUCCESS) {
	printf("\nFailed to add test suite for US2174 (%d)", rv);
	exit(1);
    }
#endif

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
    printf("\nlibcunit not installed, unit test are not enabled\n");
#endif
}


