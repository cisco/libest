/*------------------------------------------------------------------
 * cdets.c - Public API for CDETS utilities 
 *
 * October, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CDETS_UT_FILE	"./Unit-test"

/*
 * This can be used to generate the Unit-test attachment
 * for CDETS.  It automatically builds the file, which can
 * then be attached to CDETS using the addfile command on
 * an engineering server.
 */
void cdets_gen_ut_attachment (int total_tests, int tests_passed)
{
    FILE *fp;
    char cmd[256];
    char *user;
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    /*
     * Remove the old UT results
     */
    sprintf(cmd, "rm %s", CDETS_UT_FILE);
    system(cmd);

    fp = fopen(CDETS_UT_FILE, "w");

    user = getenv("USER");
    if (!user) return;

    fprintf(fp, "Unit Test Enclosure: Added %d-%d-%d by %s\n\n", 
	    tm.tm_mday, tm.tm_mon+1, tm.tm_year+1900, user);

    fprintf(fp, "*** Start of CDETS Attachment for UT Measures ***\n\n");

    fprintf(fp, "Unit Test Plan Metrics\n");
    fprintf(fp, "++Test Plan review completed: No\n");
    fprintf(fp, "++# of test cases reviewed: \n\n");
 
    fprintf(fp, "***\n");
    fprintf(fp, "Unit Test Results Metrics\n");
    fprintf(fp, "++Test Results review completed: No\n");
    fprintf(fp, "++# of test cases executed: %d\n", total_tests);
    fprintf(fp, "++# of test cases passed: %d\n", tests_passed);
    fprintf(fp, "++High/Medium Issues: 0\n");
    fprintf(fp, "++Low Issues: 0\n");
    fprintf(fp, "*** End of CDETS Attachment for UT Measures ***\n\n");

    fprintf(fp, "*** Start of CDETS Attachment for UT Documentation ***\n");
    fprintf(fp, "--Plan: Run the full CUnit test suite\n\n");

    fprintf(fp, "***\n");
    fprintf(fp, "--Results: Pass\n");
    fprintf(fp, "*** End of CDETS Attachment for UT Documentation ***\n");

    fclose(fp);
}
