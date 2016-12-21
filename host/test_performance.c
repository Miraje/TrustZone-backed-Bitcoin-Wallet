/** \file
  *
  * \brief TO DO YET!!!!
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "extern.h"
#include "prandom.h"
#include "storage_common.h"
#include "stream_comm.h"
#include "test_helpers.h"
#include "test_stream.h"
#include "tz_functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int tests_passed;
int tests_failed;
int tests_total;
clock_t start_time;
clock_t finish_time;
double time_spent;
clock_t start_test_time;
clock_t finish_test_time;
double test_time;
double total_test_time;

void reportFailurePerformance(void)
{
	tests_failed++;
	tests_total++;
	printf("\tTest %2d: FAILED\n", tests_total);
}

void reportSuccessPerformance(void)
{
	tests_passed++;
	tests_total++;
	printf("\tTest %2d: PASSED\n", tests_total);
}

void initialiseTestsPerformance(void)
{
	is_test = true;
	is_test_performance = true;

	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	total_test_time = 0;

	srand(42);

	printf("\n\n=====================================================================================================================================================\n");

	printf("Initializing the wallet storage ... ");
	createWalletStorage();
	openWalletStorage();
	printf("done\n");

	printf("Executing the test performance now.\n");

	printf("=====================================================================================================================================================\n");

	start_time = clock();

}

void finaliseTestsPerformance(void)
{
	time_t t;

	finish_time = clock();

	time_spent = ((double) (finish_time - start_time)) / CLOCKS_PER_SEC;

	is_test = false;
	is_test_stream = false;

	closeWalletStorage();
	deleteWalletStorage();

	srand((unsigned) time(&t));

	printf("\n=====================================================================================================================================================\n");

	printf("Finished executing the test performance.\n\n");

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	printf("=====================================================================================================================================================\n");

	printf("Total test time\n");

	printTime(total_test_time);
}

void startTest(char * test_description)
{
	//printf("=====================================================================================================================================================\n");
	printf("%s\n", test_description);

	start_test_time = clock();
}

void finishTest(void)
{
	finish_test_time = clock();

	/* TODO Remove CLOCKS_PER_SEC */

	test_time = ((double) (finish_test_time - start_test_time)) / CLOCKS_PER_SEC;
	total_test_time += test_time;

	printTime(test_time);

	printf("=====================================================================================================================================================\n");
}

void TestPerformance(statistics * stats)
{
	NonVolatileReturn response;
	uint8_t buffer[NV_MEMORY_SIZE];
	uint8_t exp_buffer[NV_MEMORY_SIZE];

	memset(buffer, 0, NV_MEMORY_SIZE);
	memset(exp_buffer, 8, NV_MEMORY_SIZE);

	/* Initialize tests */
	initialiseTestsPerformance();

	/* TODO: Add test performance streams here */

	/* Write in the global partition and fetch data to the cache */
	startTest("Writing in the global partition (at once). Fetch data to the cache.");

	response = nonVolatileWrite(exp_buffer, PARTITION_GLOBAL, 0, GLOBAL_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't write to global partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	/* Write in the accounts partition */
	startTest("Writing  in the accounts partition (at once). Write in the cache.");

	response = nonVolatileWrite(exp_buffer, PARTITION_ACCOUNTS, 0, ACCOUNTS_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't write to accounts partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	/* Read from the global partition */
	startTest("Reading from the global partition (at once). Read from cache.");

	response = nonVolatileRead(buffer, PARTITION_GLOBAL, 0, GLOBAL_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't read from global partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	/* Read from the accounts partition */
	startTest("Reading from the accounts partition (at once). Read from cache.");

	response = nonVolatileRead(buffer + sizeof(uint8_t)*(GLOBAL_PARTITION_SIZE), PARTITION_ACCOUNTS, 0, ACCOUNTS_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't read from accounts partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	/* Compare what was written with what was read */
	printf("Comparing what was written with what was read\n");

	if (memcmp(buffer, exp_buffer, NV_MEMORY_SIZE) != 0)
		reportFailurePerformance();
	else
		reportSuccessPerformance();

	/* Measuring the time of flush function */
	printf("=====================================================================================================================================================\n");
	startTest("Measuring the time of 'flush' function");

	response = nonVolatileFlush();

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't perform 'flush' operation.\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	memset(buffer, 0, NV_MEMORY_SIZE);

	/* Read from the global partition when data isn't cached */
	startTest("Reading from the global partition (at once). Read from secure storage.");

	response = nonVolatileRead(buffer, PARTITION_GLOBAL, 0, GLOBAL_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't read from global partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	/* Read from the accounts partition when data isn't cached */
	startTest("Reading from the accounts partition (at once). Read from secure storage.");

	response = nonVolatileRead(buffer + sizeof(uint8_t)*(GLOBAL_PARTITION_SIZE), PARTITION_ACCOUNTS, 0, ACCOUNTS_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't read from accounts partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	memset(exp_buffer, 4, NV_MEMORY_SIZE);

	/* Write in the accounts partition and fetch data to the cache */
	startTest("Writing  in the accounts partition (at once). Fetch data to the cache.");

	response = nonVolatileWrite(exp_buffer, PARTITION_ACCOUNTS, 0, ACCOUNTS_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't write to accounts partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	/* Write in the global partition */
	startTest("Writing in the global partition (at once). Write to the cache. ");

	response = nonVolatileWrite(exp_buffer, PARTITION_GLOBAL, 0, GLOBAL_PARTITION_SIZE);

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't write to global partition\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	finishTest();

	/* Measure the time it takes to a CA function call */
	response = nonVolatileCAFunctionCall();

	if (response != NV_NO_ERROR)
	{
		printf("Couldn't perform a call to the CA application\n");
		reportFailurePerformance();
	}
	else
		reportSuccessPerformance();

	/* Measure the time it takes to a TA function call */
	if (TAFunctionCall() == false)
		reportFailurePerformance();
	else
		reportSuccessPerformance();

	/* Finalize tests */
	finaliseTestsPerformance();

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}
