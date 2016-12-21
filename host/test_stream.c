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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define TOTAL_NUMBER_OF_TESTS	31
#define ARRAY_SIZE(x) 			(sizeof((x)) / sizeof((x)[0]))

int tests_passed;
int tests_failed;
int tests_total;
char * pos;
int writen_size;
int size;
int response_size;
clock_t start_time;
clock_t finish_time;
double time_spent;
char * test_responses[TOTAL_NUMBER_OF_TESTS];

const uint8_t *test_streams[] = {
	test_stream_init,
	test_stream_ping,
	test_stream_format,
	test_stream_list_wallets,
	test_stream_new_wallet,
	test_stream_list_wallets,
	test_stream_new_address,
	test_stream_get_num_addresses,
	test_stream_get_address1,
	test_stream_get_address0,
	test_stream_sign_tx,
	test_stream_sign_tx,
	test_stream_load_incorrect,
	test_stream_load_correct,
	test_stream_change_key,
	test_stream_init,
	test_stream_load_with_changed_key,
	test_stream_change_name,
	test_stream_list_wallets,
	test_stream_backup_wallet,
	test_stream_delete,
	test_stream_restore_wallet,
	test_stream_get_device_uuid,
	test_stream_get_entropy0,
	test_stream_get_entropy1,
	test_stream_get_entropy32,
	test_stream_get_entropy100,
	test_stream_ping,
	test_get_master_public_key,
	test_get_master_public_key_no_press,
	test_stream_load_no_key
};

const int test_streams_size[] = {
	ARRAY_SIZE(test_stream_init),
	ARRAY_SIZE(test_stream_ping),
	ARRAY_SIZE(test_stream_format),
	ARRAY_SIZE(test_stream_list_wallets),
	ARRAY_SIZE(test_stream_new_wallet),
	ARRAY_SIZE(test_stream_list_wallets),
	ARRAY_SIZE(test_stream_new_address),
	ARRAY_SIZE(test_stream_get_num_addresses),
	ARRAY_SIZE(test_stream_get_address1),
	ARRAY_SIZE(test_stream_get_address0),
	ARRAY_SIZE(test_stream_sign_tx),
	ARRAY_SIZE(test_stream_sign_tx),
	ARRAY_SIZE(test_stream_load_incorrect),
	ARRAY_SIZE(test_stream_load_correct),
	ARRAY_SIZE(test_stream_change_key),
	ARRAY_SIZE(test_stream_init),
	ARRAY_SIZE(test_stream_load_with_changed_key),
	ARRAY_SIZE(test_stream_change_name),
	ARRAY_SIZE(test_stream_list_wallets),
	ARRAY_SIZE(test_stream_backup_wallet),
	ARRAY_SIZE(test_stream_delete),
	ARRAY_SIZE(test_stream_restore_wallet),
	ARRAY_SIZE(test_stream_get_device_uuid),
	ARRAY_SIZE(test_stream_get_entropy0),
	ARRAY_SIZE(test_stream_get_entropy1),
	ARRAY_SIZE(test_stream_get_entropy32),
	ARRAY_SIZE(test_stream_get_entropy100),
	ARRAY_SIZE(test_stream_ping),
	ARRAY_SIZE(test_get_master_public_key),
	ARRAY_SIZE(test_get_master_public_key_no_press),
	ARRAY_SIZE(test_stream_load_no_key)
};

const char * test_streams_description[] = {
	test_stream_init_description,
	test_stream_ping_description,
	test_stream_format_description,
	test_stream_list_wallets_description,
	test_stream_new_wallet_description,
	test_stream_list_wallets_description,
	test_stream_new_address_description,
	test_stream_get_num_addresses_description,
	test_stream_get_address1_description,
	test_stream_get_address0_description,
	test_stream_sign_tx_description,
	test_stream_sign_tx_description,
	test_stream_load_incorrect_description,
	test_stream_load_correct_description,
	test_stream_change_key_description,
	test_stream_init_description,
	test_stream_load_with_changed_key_description,
	test_stream_change_name_description,
	test_stream_list_wallets_description,
	test_stream_backup_wallet_description,
	test_stream_delete_description,
	test_stream_restore_wallet_description,
	test_stream_get_device_uuid_description,
	test_stream_get_entropy0_description,
	test_stream_get_entropy1_description,
	test_stream_get_entropy32_description,
	test_stream_get_entropy100_description,
	test_stream_ping_description,
	test_get_master_public_key_description,
	test_get_master_public_key_no_press_description,
	test_stream_load_no_key_description
};

const char * expected_responses[] = {
	response_stream_init,
	response_stream_ping,
	response_stream_format,
	response_stream_list_wallets_0,
	response_stream_new_wallet,
	response_stream_list_wallets_1,
	response_stream_new_address,
	response_stream_get_num_addresses,
	response_stream_get_address1,
	response_stream_get_address0,
	response_stream_sign_tx0,
	response_stream_sign_tx1,
	response_stream_load_incorrect,
	response_stream_load_correct,
	response_stream_change_key,
	response_stream_init,
	response_stream_load_with_changed_key,
	response_stream_change_name,
	response_stream_list_wallets_2,
	response_stream_backup_wallet,
	response_stream_delete,
	response_stream_restore_wallet,
	response_stream_get_device_uuid,
	response_stream_get_entropy0,
	response_stream_get_entropy1,
	response_stream_get_entropy32,
	response_stream_get_entropy100,
	response_stream_ping,
	response_get_master_public_key,
	response_get_master_public_key_no_press,
	response_stream_load_no_key
};

void writeResponseByte(uint8_t byte)
{
	if (is_test_stream && size < response_size)
	{
		writen_size = sprintf(pos, "%02x", (int)byte);
		pos += writen_size;
		size += writen_size;
	}
}

void checkResponseValidity(int test_number)
{
	if (strcmp(test_responses[test_number], expected_responses[test_number]) != 0)
	{
		printf("Test FAILED.\n");
		tests_failed++;
	}
	else
	{
		printf("Test PASSSED.\n");
		tests_passed++;
	}
}

void initialiseTestsStreams(void)
{
	int i;

	is_test = true;
	is_test_stream = true;

	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	srand(42);	/* Make sure tests which rely on rand() are deterministic */

	for (i = 0; i < TOTAL_NUMBER_OF_TESTS; i++)
		test_responses[i] = (char*)malloc(strlen(expected_responses[i])*sizeof(char) + 1);

	printf("\n\n=====================================================================================================================================================\n");

	printf("Initializing the wallet storage ... ");
	createWalletStorage();
	openWalletStorage();
	printf("done\n");

	printf("Initializing the default entropy pool ... ");
	initialiseDefaultEntropyPool();
	printf("done\n");

	printf("Executing the test streams now.\n");

	printf("=====================================================================================================================================================\n");

	start_time = clock();
}

void finaliseTestsStreams(void)
{
	int i;
	time_t t;

	finish_time = clock();

	time_spent = ((double) (finish_time - start_time)) / CLOCKS_PER_SEC;

	is_test = false;
	is_test_stream = false;

	closeWalletStorage();
	deleteWalletStorage();

	srand((unsigned) time(&t));

	printf("Finished executing the test streams.\n\n");

	for (i = 0; i < TOTAL_NUMBER_OF_TESTS; i++)
		free(test_responses[i]);

	//printf("IT took %f seconds to execute. \n", time_spent);

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	printf("=====================================================================================================================================================\n");
}

/** Test response of processPacket() for a given test stream.
  * \param test_stream The test stream data to use.
  * \param size The length of the test stream, in bytes.
  */
static void sendOneTestStream(const uint8_t *test_stream, uint32_t size)
{
	setTestInputStream(test_stream, size);

	processPacket();

	printf("\n");
}

/** Wrapper around sendOneTestStream() that covers its most common use
  * case (use of a constant byte array). */
#define SEND_ONE_TEST_STREAM(x, y)	sendOneTestStream(x, (uint32_t)y);

/** Tests the response of processPacket() for a set of test streams
  */
void TestStreams(statistics * stats)
{
	int i;
	int j;

	initialiseTestsStreams();

	for (i = 0; i < TOTAL_NUMBER_OF_TESTS; i++)
	{
		size = 0;
		response_size = strlen(expected_responses[i]);
		pos = test_responses[i];

		printf("TEST STREAM: %d\n", i);
		printf("Message sent to device: %s\n", test_streams_description[i]);

		if (i == 6)
		{
			for (j = 0; j < 4; j++)
			{
				printf("Creating a new address [%d]\n", j+1);
				SEND_ONE_TEST_STREAM(test_streams[i], test_streams_size[i]);
			}
		}
		else
			SEND_ONE_TEST_STREAM(test_streams[i], test_streams_size[i]);

		checkResponseValidity(i);

		printf("=====================================================================================================================================================\n");
	}

	tests_total = i;

	finaliseTestsStreams();

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}

void TestPerformanceStreams(statistics * stats)
{
	int i;
	int j;
	clock_t start_test_time;
	clock_t finish_test_time;
	double test_time;
	double total_test_time = 0;

	initialiseTestsStreams();

	for (i = 0; i < TOTAL_NUMBER_OF_TESTS; i++)
	{
		size = 0;
		response_size = strlen(expected_responses[i]);
		pos = test_responses[i];

		printf("TEST STREAM: %d\n", i);
		printf("Message sent to device: %s\n", test_streams_description[i]);

		if (i == 6)
		{
			start_test_time = clock();
			for (j = 0; j < 4; j++)
			{
				printf("Creating a new address [%d]\n", j+1);
				SEND_ONE_TEST_STREAM(test_streams[i], test_streams_size[i]);
			}
			finish_test_time = clock();
		}
		else
		{
			start_test_time = clock();
			SEND_ONE_TEST_STREAM(test_streams[i], test_streams_size[i]);
			finish_test_time = clock();
		}

		checkResponseValidity(i);

		test_time = ((double) (finish_test_time - start_test_time)) / CLOCKS_PER_SEC;
		total_test_time += test_time;

		printTime(test_time);

		printf("=====================================================================================================================================================\n");
	}

	tests_total = i;

	finaliseTestsStreams();

	printf("Total tests time");
	printTime(total_test_time);

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}
