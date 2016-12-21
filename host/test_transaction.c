/** \file
  *
  * \brief TO DO YET!!!!
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "endian.h"
#include "extern.h"
#include "storage_common.h"
#include "stream_comm.h"
#include "test_helpers.h"
#include "test_transaction.h"
#include "transaction.h"
#include "tz_functions.h"
#include "user_interface.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int tests_passed;
int tests_failed;
int tests_total;
clock_t start_time;
clock_t finish_time;
double time_spent;

/** After each call to generateTestTransaction(), this will contain the offset
  * within the "full" transaction where the main transaction begins. */
static uint32_t main_offset;

void reportFailureTransaction(void)
{
	tests_failed++;
	tests_total++;
	printf("\tTest %2d: FAILED\n", tests_total);
}

void reportSuccessTransaction(void)
{
	tests_passed++;
	tests_total++;
	printf("\tTest %2d: PASSED\n", tests_total);
}

/** Check that the number of outputs seen is as expected.
  * \param target The expected number of outputs.
  */
static void checkOutputsSeen(int target)
{
	if (num_outputs_seen != target)
	{
		printf("Expected to see %d outputs, got %d\n", target, num_outputs_seen);
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();
}

/** Set the input stream to some transaction data and attempt to parse that
  * transaction.
  * \param buffer The test transaction data. If this is NULL, the input stream
  *               will be set to an infinite stream of zeroes.
  * \param length The length of the transaction, in number of bytes.
  * \param name The test name of the transaction. This is displayed on stdout
  *             if a test fails.
  * \param expected_return The expected return value of parseTransaction().
  */
static void testTransaction(const uint8_t *buffer, uint32_t length, const char *name, TransactionErrors expected_return)
{
	uint8_t sig_hash[32];
	uint8_t transaction_hash[32];
	TransactionErrors r;

	clearOutputsSeen();

	if (buffer == NULL)
		setInfiniteZeroInputStream();
	else
		setTestInputStream(buffer, length);

	r = parseTransaction(sig_hash, transaction_hash, length);

	/* Check return value is what is expected. */
	if (r != expected_return)
	{
		printf("parseTransaction() returned unexpected value for transaction \"%s\"\n", name);
		printf("Expected: %d, got: %d\n", (int)expected_return, (int)r);
		reportFailureTransaction();
	}
	else
	{
		/* Then check if all bytes in the transaction were consumed. */
		if (!isEndOfTransactionData())
		{
			printf("parseTransaction() didn't eat everything for transaction \"%s\"\n", name);
			reportFailureTransaction();
		}
		else
		{
			/* Then check that there was no attempt to read past the end of the transaction. */
			if (transaction_data_index > transaction_length)
			{
				printf("parseTransaction() read past end for transaction \"%s\"\n", name);
				reportFailureTransaction();
			}
			else
				reportSuccessTransaction();
		}
	}
}

/** This is just like testTransaction(), except this prepends
  * #good_input_transaction (and the is_ref bytes) to the test transaction data.
  * \param buffer See testTransaction().
  * \param length See testTransaction().
  * \param name See testTransaction().
  * \param expected_return See testTransaction().
  */
static void prependGoodInputTestTransaction(const uint8_t *buffer, uint32_t length, const char *name, TransactionErrors expected_return)
{
	uint8_t *new_buffer;
	uint32_t new_length;

	if (length > (0xffffffff - (sizeof(good_input_transaction) + 2)))
	{
		/* length + sizeof(good_input_transaction) + 2 will overflow. */
		printf("Unexpected fatal error: length too big in prependGoodInputTestTransaction()\n");
		exit(1);
	}

	new_length = length + sizeof(good_input_transaction) + 2;

	new_buffer = malloc(new_length);

	new_buffer[0] = 0x01; /* is_ref = 1 (input) */

	memcpy(&(new_buffer[1]), good_input_transaction, sizeof(good_input_transaction));

	new_buffer[sizeof(good_input_transaction) + 1] = 0x00;	/* is_ref = 0 (main) */

	memcpy(&(new_buffer[sizeof(good_input_transaction) + 2]), buffer, length);

	testTransaction(new_buffer, new_length, name, expected_return);

	free(new_buffer);
}

/** This is just like testTransaction(), except this prepends
  * #p2sh_test_prepend to the test transaction data.
  * \param buffer See testTransaction().
  * \param length See testTransaction().
  * \param name See testTransaction().
  * \param expected_return See testTransaction().
  */
static void prependGoodP2SHInputsTestTransaction(const uint8_t *buffer, uint32_t length, const char *name, TransactionErrors expected_return)
{
	uint8_t *new_buffer;
	uint32_t new_length;

	if (length > (0xffffffff - sizeof(p2sh_test_prepend)))
	{
		/* length + sizeof(p2sh_test_prepend) will overflow. */
		printf("Unexpected fatal error: length too big in prependGoodP2SHInputsTestTransaction()\n");
		exit(1);
	}

	new_length = length + sizeof(p2sh_test_prepend);
	new_buffer = malloc(new_length);

	memcpy(new_buffer, p2sh_test_prepend, sizeof(p2sh_test_prepend));
	memcpy(&(new_buffer[sizeof(p2sh_test_prepend)]), buffer, length);

	testTransaction(new_buffer, new_length, name, expected_return);

	free(new_buffer);
}

/** Generate a test transaction with the specified number of inputs and
  * outputs. This generates a "full" transaction, which all (referenced)
  * input transactions followed by the main (spending) transaction.
  * The structure of transactions was obtained from
  * https://en.bitcoin.it/wiki/Protocol_specification on 11-June-2012.
  * \param out_length The length of the generated transaction will be written
  *                   here.
  * \param num_inputs The number of inputs to include in the transaction.
  * \param num_outputs The number of outputs to include in the transaction.
  * \return A pointer to a byte array containing the transaction data. This
  *         array must eventually be freed by the caller.
  */
static uint8_t *generateTestTransaction(uint32_t *out_length, uint32_t num_inputs, uint32_t num_outputs)
{
	uint8_t *buffer;
	uint32_t ptr;
	uint32_t i;
	size_t malloc_size;
	uint8_t temp[20];
	int j;

	malloc_size = num_inputs * sizeof(one_input);
	malloc_size += num_inputs * (sizeof(good_input_transaction) + 1);
	malloc_size += num_outputs * sizeof(one_output);
	malloc_size += sizeof(good_main_transaction);
	malloc_size += 100;	/* just to be sure */
	buffer = malloc(malloc_size);
	ptr = 0;

	/* Write input transactions. */
	for (i = 0; i < num_inputs; i++)
	{
		buffer[ptr] = 0x01; /* is_ref = 1 (input) */
		ptr++;
		memcpy(&(buffer[ptr]), good_input_transaction, sizeof(good_input_transaction));
		ptr += sizeof(good_input_transaction);
	}

	buffer[ptr] = 0x00; /* is_ref = 0 (main) */
	ptr++;

	/* The main transaction begins here. */
	main_offset = ptr;

	/* Write version. */
	writeU32LittleEndian(&(buffer[ptr]), 0x00000001);

	ptr += 4;

	/* Write number of inputs. */
	if (num_inputs < 0xfd)
	{
		buffer[ptr] = (uint8_t)num_inputs;
		ptr++;
	}
	else if (num_inputs <= 0xffff)
	{
		buffer[ptr] = 0xfd;
		ptr++;
		buffer[ptr] = (uint8_t)num_inputs;
		ptr++;
		buffer[ptr] = (uint8_t)(num_inputs >> 8);
		ptr++;
	}
	else
	{
		buffer[ptr] = 0xfe;
		ptr++;
		writeU32LittleEndian(&(buffer[ptr]), num_inputs);
		ptr += 4;
	}

	/* Write inputs. */
	for (i = 0; i < num_inputs; i++)
	{
		memcpy(&(buffer[ptr]), one_input, sizeof(one_input));
		ptr += sizeof(one_input);
	}

	/* Write number of outputs. */
	if (num_outputs < 0xfd)
	{
		buffer[ptr] = (uint8_t)num_outputs;
		ptr++;
	}
	else if (num_outputs <= 0xffff)
	{
		buffer[ptr] = 0xfd;
		ptr++;
		buffer[ptr] = (uint8_t)num_outputs;
		ptr++;
		buffer[ptr] = (uint8_t)(num_outputs >> 8);
		ptr++;
	}
	else
	{
		buffer[ptr] = 0xfe;
		ptr++;
		writeU32LittleEndian(&(buffer[ptr]), num_outputs);
		ptr += 4;
	}

	/* Write outputs. */
	for (i = 0; i < num_outputs; i++)
	{
		memcpy(&(buffer[ptr]), one_output, sizeof(one_output));
		if (i == 0)
		{
			memcpy(&(buffer[ptr]), output_amount1, sizeof(output_amount1));
			memcpy(&(buffer[ptr + 12]), output_address1, sizeof(output_address1));
		}
		else if (i == 1)
		{
			memcpy(&(buffer[ptr]), output_amount2, sizeof(output_amount2));
			memcpy(&(buffer[ptr + 12]), output_address2, sizeof(output_address2));
		}
		else
		{
			/* Use random amount/address. */
			memset(temp, 0, 8);

			/* Make sure it's small enough that the transaction fee is always positive. */
			for (j = 0; j < 2; j++)
				temp[j] = (uint8_t)(rand() & 0xff);

			memcpy(&(buffer[ptr]), temp, 8);

			for (j = 0; j < 20; j++)
				temp[j] = (uint8_t)(rand() & 0xff);

			memcpy(&(buffer[ptr + 12]), temp, 20);
		}

		ptr += sizeof(one_output);
	}

	/* Write locktime. */
	writeU32LittleEndian(&(buffer[ptr]), 0x00000000);
	ptr += 4;

	/* Write hashtype. */
	writeU32LittleEndian(&(buffer[ptr]), 0x00000001);
	ptr += 4;

	*out_length = ptr;

	return buffer;
}

void initialiseTestsTransaction(void)
{
	is_test = true;
	is_test_transaction = true;

	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	srand(42);	/* Make sure tests which rely on rand() are deterministic */

	printf("\n\n=====================================================================================================================================================\n");

	printf("Initializing the wallet storage ... ");
	createWalletStorage();
	openWalletStorage();
	printf("done\n");

	printf("Initializing the default entropy pool ... ");
	initialiseDefaultEntropyPool();
	printf("done\n");

	printf("Executing the tests for transaction now.\n");

	printf("=====================================================================================================================================================\n");

	start_time = clock();
}

void finaliseTestsTransaction(void)
{
	time_t t;

	finish_time = clock();

	is_test = false;
	is_test_transaction = false;

	broken_hwrng = false;

	time_spent = ((double) (finish_time - start_time)) / CLOCKS_PER_SEC;

	closeWalletStorage();
	deleteWalletStorage();

	srand((unsigned) time(&t));

	printf("\n=====================================================================================================================================================\n");

	printf("Finished executing the tests for transaction\n\n");

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	printf("=====================================================================================================================================================\n\n");
}

void TestTransaction(statistics * stats)
{
	int i;
	char name[1024];
	uint8_t bad_main_transaction[sizeof(good_main_transaction)];
	uint8_t *generated_transaction;
	uint32_t length;
	uint8_t big_amount_buffer[sizeof(big_amount_full_transaction)];
	uint32_t test_hs[8];
	uint8_t sig_hash[32];
	uint8_t transaction_hash[32];
	uint8_t calculated_sig_hash[32];
	uint8_t calculated_transaction_hash[32];
	uint8_t sig_hash_input_changed[32];
	uint8_t transaction_hash_input_changed[32];
	uint8_t sig_hash_output_changed[32];
	uint8_t transaction_hash_output_changed[32];
	uint8_t signature[MAX_SIGNATURE_LENGTH];
	uint8_t signature_length;
	uint8_t bad_full_transaction[sizeof(good_full_transaction)];
	int num_tests;

	initialiseTestsTransaction();

	/* Test the transaction parser on some transactions which have invalid lengths. */
	printf("Test the transaction parser on some transactions which have invalid lengths\n");

	testTransaction(good_full_transaction, 0, "blank", TRANSACTION_INVALID_FORMAT);

	testTransaction(NULL, MAX_TRANSACTION_SIZE + 1, "toobig", TRANSACTION_TOO_LARGE);

	/* Length = 0xffffffff left to end. */

	/* Test the transaction parser on a known good transaction. */
	printf("Test the transaction parser on a known good transaction\n");

	testTransaction(good_full_transaction, sizeof(good_full_transaction), "good", TRANSACTION_NO_ERROR);

	/*
	 * Sanity check: prependGoodInputTestTransaction() with the main
	 * transaction from  good_full_transaction should produce identical
	 * results to the test immediately above.
	 */
	printf(" Sanity check\n");

	prependGoodInputTestTransaction(good_main_transaction, sizeof(good_main_transaction), "good2", TRANSACTION_NO_ERROR);

	/* Truncate the good transaction and check that the transaction parser doesn't choke. */
	printf("Truncate the good transaction and check that the transaction parser doesn't choke\n");

	for (i = 0; i < (int)sizeof(good_full_transaction); i++)
	{
		sprintf(name, "truncate%d", i);
		testTransaction(good_full_transaction, (uint32_t)i, name, TRANSACTION_INVALID_FORMAT);
	}

	/* Corrupt the version field. */
	printf("Corrupt the version field\n");

	memcpy(bad_main_transaction, good_main_transaction, sizeof(good_main_transaction));
	writeU32LittleEndian(bad_main_transaction, 0x00000000);	/* version */

	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badversion", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(bad_main_transaction, 0xFFFFFFFF);	/* version */

	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badversion2", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(bad_main_transaction, 0x00000002);	/* version */

	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badversion3", TRANSACTION_NON_STANDARD);

	/* Say that there are inputs, but don't actually include the inputs. */
	printf("Say that there are inputs, but don't actually include the inputs\n");

	prependGoodInputTestTransaction(inputs_removed_transaction, sizeof(inputs_removed_transaction), "noinputs", TRANSACTION_INVALID_FORMAT);

	memcpy(bad_main_transaction, inputs_removed_transaction, sizeof(inputs_removed_transaction));

	bad_main_transaction[4] = 0xfc;	/* Number of inputs */

	prependGoodInputTestTransaction(bad_main_transaction, sizeof(inputs_removed_transaction), "noinputs2", TRANSACTION_INVALID_FORMAT);

	/*
	 * A sanity check: since generateTestTransaction() uses data derived
	 * from good_full_transaction, using generateTestTransaction() with
	 * num_inputs set to 1 should return a transaction identical to
	 * good_full_transaction.
	 */
	printf("A sanity check\n");

	generated_transaction = generateTestTransaction(&length, 1, 2);

	if (memcmp(generated_transaction, good_full_transaction, length))
	{
		printf("generateTestTransaction() sanity check failed\n");
		exit(1);
	}

	free(generated_transaction);

	/* Include the wrong number of inputs. */
	printf("Include the wrong number of inputs\n");

	generated_transaction = generateTestTransaction(&length, 2, 2);

	generated_transaction[main_offset + 4] = 0x03; /* number of inputs (too many) */

	testTransaction(generated_transaction, length, "wronginputs", TRANSACTION_INVALID_FORMAT);

	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 7, 2);

	generated_transaction[main_offset + 4] = 0x02; /* number of inputs (too few) */

	/*
	 * The transaction parser should return TRANSACTION_INVALID_REFERENCE
	 * because the input transaction hashes don't match the input
	 * references.
	 */
	printf("Testing TRANSACTION_INVALID_REFERENCE\n");

	testTransaction(generated_transaction, length, "wronginputs2", TRANSACTION_INVALID_REFERENCE);
	free(generated_transaction);

	/* Include no inputs. */
	printf("Include no inputs\n");

	generated_transaction = generateTestTransaction(&length, 0, 2);
	testTransaction(generated_transaction, length, "noinputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	/*
	 * The transaction parser should successfully parse transactions with up
	 * to MAX_INPUTS inputs.
	 */
	printf("The transaction parser should successfully parse transactions with up to MAX_INPUTS inputs\n");

	generated_transaction = generateTestTransaction(&length, 1, 2);
	testTransaction(generated_transaction, length, "1input", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 2, 2);
	testTransaction(generated_transaction, length, "2inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	/* Try numbers close to varint boundaries... */
	printf("Try numbers close to varint boundaries...\n");

	generated_transaction = generateTestTransaction(&length, 0xfb, 2);
	testTransaction(generated_transaction, length, "251inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 0xfc, 2);
	testTransaction(generated_transaction, length, "252inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 0xfd, 2);
	testTransaction(generated_transaction, length, "253inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 0xfe, 2);
	testTransaction(generated_transaction, length, "254inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 0xff, 2);
	testTransaction(generated_transaction, length, "255inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 0x100, 2);
	testTransaction(generated_transaction, length, "256inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 0x101, 2);
	testTransaction(generated_transaction, length, "257inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 0x102, 2);
	testTransaction(generated_transaction, length, "258inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, MAX_INPUTS - 2, 2);
	testTransaction(generated_transaction, length, "MAX-2inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, MAX_INPUTS - 1, 2);
	testTransaction(generated_transaction, length, "MAX-1inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, MAX_INPUTS, 2);
	testTransaction(generated_transaction, length, "MAXinputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	/* The transaction parser should reject transactions with too many inputs. */
	printf("The transaction parser should reject transactions with too many inputs\n");

	generated_transaction = generateTestTransaction(&length, MAX_INPUTS + 1, 2);
	testTransaction(generated_transaction, length, "MAX+2inputs", TRANSACTION_TOO_MANY_INPUTS);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, MAX_INPUTS + 2, 2);
	testTransaction(generated_transaction, length, "MAX+2inputs", TRANSACTION_TOO_MANY_INPUTS);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 10, 2);
	generated_transaction[main_offset + 4] = 0xfe;

	writeU32LittleEndian(&(generated_transaction[main_offset + 5]), 0xffffffff); // number of inputs
	testTransaction(generated_transaction, length, "stupidinputs", TRANSACTION_TOO_MANY_INPUTS);
	free(generated_transaction);

	/*
	 * Technically, a blank script is a valid script. The transaction parser
	 * doesn't care what the input script is, so it should accept blank
	 * scripts.
	 */
	printf("The transaction parser doesn't care what the input script is, so it should accept blank scripts\n");

	prependGoodInputTestTransaction(good_main_transaction_blank_script, sizeof(good_main_transaction_blank_script), "blankscript", TRANSACTION_NO_ERROR);

	/* Corrupt the sequence field. */
	printf("Corrupt the sequence field\n");

	memcpy(bad_main_transaction, good_main_transaction, sizeof(good_main_transaction));
	writeU32LittleEndian(&(bad_main_transaction[67]), 0x00000000);	/* Sequence */

	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badsequence", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(&(bad_main_transaction[67]), 0xFFFFFFFE);	/* Sequence */

	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badsequence2", TRANSACTION_NON_STANDARD);

	/* Say that there are outputs, but don't actually include the outputs. */
	printf("Say that there are outputs, but don't actually include the outputs\n");

	testTransaction(outputs_removed_transaction, sizeof(outputs_removed_transaction), "nooutputs", TRANSACTION_INVALID_FORMAT);

	generated_transaction = malloc(sizeof(outputs_removed_transaction));

	memcpy(generated_transaction, outputs_removed_transaction, sizeof(outputs_removed_transaction));

	generated_transaction[335] = 0xfc;	/* Number of outputs */

	testTransaction(generated_transaction, sizeof(outputs_removed_transaction), "nooutputs2", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	/* Include the wrong number of outputs. */
	printf("Include the wrong number of outputs\n");

	testTransaction(too_many_outputs_transaction, sizeof(too_many_outputs_transaction), "wrongoutputs", TRANSACTION_INVALID_FORMAT);
	generated_transaction = generateTestTransaction(&length, 1, 9);
	generated_transaction[main_offset + 71] = 0x01;	/* Number of outputs (too few) */

	/*
	 * The transaction parser will return TRANSACTION_NON_STANDARD because it
	 * interprets the first 4 bytes of one of the outputs as locktime. Those
	 * bytes won't be 0x00000000, so it will think the transaction is non
	 * standard.
	 */
	printf("Testing TRANSACTION_NON_STANDARD\n");

	testTransaction(generated_transaction, length, "wrongoutputs2", TRANSACTION_NON_STANDARD);
	free(generated_transaction);

	/* Include no outputs. */
	printf("Include no outputs\n");

	generated_transaction = generateTestTransaction(&length, 1, 0);
	testTransaction(generated_transaction, length, "nooutputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	/* The transaction parser should successfully parse transactions with up to MAX_OUTPUTS outputs. */
	printf("The transaction parser should successfully parse transactions with up to MAX_OUTPUTS outputs\n");

	generated_transaction = generateTestTransaction(&length, 1, 1);
	testTransaction(generated_transaction, length, "1output", TRANSACTION_NO_ERROR);
	checkOutputsSeen(1);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, 2);
	testTransaction(generated_transaction, length, "2outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(2);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, 3);
	testTransaction(generated_transaction, length, "3outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(3);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS - 2);
	testTransaction(generated_transaction, length, "MAX-2outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(MAX_OUTPUTS - 2);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS - 1);
	testTransaction(generated_transaction, length, "MAX-1outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(MAX_OUTPUTS - 1);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS);
	testTransaction(generated_transaction, length, "MAXoutputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(MAX_OUTPUTS);
	free(generated_transaction);

	/* The transaction parser should reject transactions with more than MAX_OUTPUTS outputs. */
	printf("The transaction parser should reject transactions with more than MAX_OUTPUTS outputs\n");

	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS + 1);
	testTransaction(generated_transaction, length, "MAX+1output", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS + 2);
	testTransaction(generated_transaction, length, "MAX+2outputs", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS + 3);
	testTransaction(generated_transaction, length, "MAX+3outputs", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);

	generated_transaction = generateTestTransaction(&length, 1, 20);
	generated_transaction[main_offset + 71] = 0xfe;

	writeU32LittleEndian(&(generated_transaction[main_offset + 72]), 0xffffffff);	/* Number of outputs */
	testTransaction(generated_transaction, length, "stupidoutputs", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);

	/* Try number of outputs = 2 ^ 64 - 1, just to screw with the varint reader. */
	printf("Try number of outputs = 2 ^ 64 - 1, just to screw with the varint reader\n");

	generated_transaction = generateTestTransaction(&length, 1, 20);
	generated_transaction[main_offset + 71] = 0xff;

	writeU32LittleEndian(&(generated_transaction[main_offset + 72]), 0xffffffff);	/* Number of outputs */
	writeU32LittleEndian(&(generated_transaction[main_offset + 76]), 0xffffffff);	/* Number of outputs */

	/* The transaction parser returns TRANSACTION_INVALID_FORMAT because the varint reader can't read uint64_t. */
	printf("The transaction parser returns TRANSACTION_INVALID_FORMAT because the varint reader can't read uint64_t\n");

	testTransaction(generated_transaction, length, "stupideroutputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	/*
	 * The transaction parser does care about output scripts, so it should
	 * reject a blank output script as non-standard.
	 */
	printf("Reject a blank output script as non-standard\n");

	prependGoodInputTestTransaction(good_test_transaction_blank_output_script, sizeof(good_test_transaction_blank_output_script), "blankoutput", TRANSACTION_NON_STANDARD);

	/* Check that the transaction parser recognises (and rejects) non standard transactions. */
	printf("Check that the transaction parser recognises (and rejects) non standard transactions\n");

	prependGoodInputTestTransaction(non_standard1, sizeof(non_standard1), "non_standard1", TRANSACTION_NON_STANDARD);
	prependGoodInputTestTransaction(non_standard2, sizeof(non_standard2), "non_standard2", TRANSACTION_NON_STANDARD);
	prependGoodInputTestTransaction(non_standard3, sizeof(non_standard3), "non_standard3", TRANSACTION_NON_STANDARD);
	prependGoodInputTestTransaction(non_standard4, sizeof(non_standard4), "non_standard4", TRANSACTION_NON_STANDARD);
	prependGoodInputTestTransaction(non_standard5, sizeof(non_standard5), "non_standard5", TRANSACTION_NON_STANDARD);
	prependGoodInputTestTransaction(non_standard6, sizeof(non_standard6), "non_standard6", TRANSACTION_NON_STANDARD);
	prependGoodInputTestTransaction(non_standard7, sizeof(non_standard7), "non_standard7", TRANSACTION_NON_STANDARD);

	/* Try some output amounts near and above max_money. */
	printf("Try some output amounts near and above max_money\n");

	memcpy(big_amount_buffer, big_amount_full_transaction, sizeof(big_amount_full_transaction));
	writeU32LittleEndian(&(big_amount_buffer[301]), 0x5A073FFF); // amount (least significant)
	writeU32LittleEndian(&(big_amount_buffer[305]), 0x000775F0); // amount (most significant)
	testTransaction(big_amount_buffer, sizeof(big_amount_full_transaction), "maxmoney-1", TRANSACTION_NO_ERROR);

	writeU32LittleEndian(&(big_amount_buffer[301]), 0x5A074000); // amount (least significant)
	writeU32LittleEndian(&(big_amount_buffer[305]), 0x000775F0); // amount (most significant)
	testTransaction(big_amount_buffer, sizeof(big_amount_full_transaction), "maxmoney", TRANSACTION_NO_ERROR);

	writeU32LittleEndian(&(big_amount_buffer[301]), 0x5A074001); // amount (least significant)
	writeU32LittleEndian(&(big_amount_buffer[305]), 0x000775F0); // amount (most significant)
	testTransaction(big_amount_buffer, sizeof(big_amount_full_transaction), "maxmoney+1", TRANSACTION_INVALID_AMOUNT);

	writeU32LittleEndian(&(big_amount_buffer[301]), 0x5A074000); // amount (least significant)
	writeU32LittleEndian(&(big_amount_buffer[305]), 0x000775F1); // amount (most significant)
	testTransaction(big_amount_buffer, sizeof(big_amount_full_transaction), "biggermoney", TRANSACTION_INVALID_AMOUNT);

	writeU32LittleEndian(&(big_amount_buffer[301]), 0xFFFFFFFF); // amount (least significant)
	writeU32LittleEndian(&(big_amount_buffer[305]), 0xFFFFFFFF); // amount (most significant)
	testTransaction(big_amount_buffer, sizeof(big_amount_full_transaction), "biggestmoney", TRANSACTION_INVALID_AMOUNT);

	/* Test the transaction parser on a known good P2SH transaction. */
	printf("Test the transaction parser on a known good P2SH transaction\n");

	prependGoodP2SHInputsTestTransaction(good_p2sh_transaction, sizeof(good_p2sh_transaction), "good_p2sh", TRANSACTION_NO_ERROR);

	/* Corrupt some of the P2SH output script bytes, making it non-standard. */
	printf("Corrupt some of the P2SH output script bytes, making it non-standard\n");

	generated_transaction = malloc(sizeof(good_p2sh_transaction));
	memcpy(generated_transaction, good_p2sh_transaction, sizeof(good_p2sh_transaction));

	generated_transaction[344] = 0xaa;
	prependGoodP2SHInputsTestTransaction(generated_transaction, sizeof(good_p2sh_transaction), "bad_p2sh1", TRANSACTION_NON_STANDARD);
	memcpy(generated_transaction, good_p2sh_transaction, sizeof(good_p2sh_transaction));

	generated_transaction[345] = 0x15;
	prependGoodP2SHInputsTestTransaction(generated_transaction, sizeof(good_p2sh_transaction), "bad_p2sh2", TRANSACTION_NON_STANDARD);
	memcpy(generated_transaction, good_p2sh_transaction, sizeof(good_p2sh_transaction));

	generated_transaction[366] = 0x88;
	prependGoodP2SHInputsTestTransaction(generated_transaction, sizeof(good_p2sh_transaction), "bad_p2sh3", TRANSACTION_NON_STANDARD);
	free(generated_transaction);

	prependGoodP2SHInputsTestTransaction(nonstandard_p2sh_transaction1, sizeof(nonstandard_p2sh_transaction1), "nonstandard_p2sh_transaction1", TRANSACTION_NON_STANDARD);
	prependGoodP2SHInputsTestTransaction(nonstandard_p2sh_transaction2, sizeof(nonstandard_p2sh_transaction2), "nonstandard_p2sh_transaction2", TRANSACTION_NON_STANDARD);
	prependGoodP2SHInputsTestTransaction(nonstandard_p2sh_transaction3, sizeof(nonstandard_p2sh_transaction3), "nonstandard_p2sh_transaction3", TRANSACTION_NON_STANDARD);
	prependGoodP2SHInputsTestTransaction(nonstandard_p2sh_transaction4, sizeof(nonstandard_p2sh_transaction4), "nonstandard_p2sh_transaction4", TRANSACTION_NON_STANDARD);

	/* Truncate the good P2SH transaction and check that the transaction parser doesn't choke. */
	printf("Truncate the good P2SH transaction and check that the transaction parser doesn't choke\n");

	for (i = 0; i < (int)sizeof(good_p2sh_transaction); i++)
	{
		sprintf(name, "truncate_p2sh%d", i);
		prependGoodP2SHInputsTestTransaction(good_p2sh_transaction, (uint32_t)i, name, TRANSACTION_INVALID_FORMAT);
	}

	/* Corrupt the locktime field. */
	printf("Corrupt the locktime field\n");

	memcpy(bad_main_transaction, good_main_transaction, sizeof(good_main_transaction));
	writeU32LittleEndian(&(bad_main_transaction[140]), 0x00000001);	/* Locktime */
	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badlocktime", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(&(bad_main_transaction[140]), 0xFFFFFFFF);	/* Locktime */
	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badlocktime2", TRANSACTION_NON_STANDARD);

	/* Corrupt the hashtype field. */
	printf("Corrupt the hashtype field\n");

	memcpy(bad_main_transaction, good_main_transaction, sizeof(good_main_transaction));
	writeU32LittleEndian(&(bad_main_transaction[144]), 0x00000000);	/* Hashtype */
	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badhashtype", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(&(bad_main_transaction[144]), 0xFFFFFFFF);	/* Hashtype */
	prependGoodInputTestTransaction(bad_main_transaction, sizeof(good_main_transaction), "badhashtype2", TRANSACTION_NON_STANDARD);

	/* Add junk data to the end of a good transaction. */
	printf("Add junk data to the end of a good transaction\n");

	length = sizeof(good_full_transaction) + 1;
	generated_transaction = malloc(length);

	memcpy(generated_transaction, good_full_transaction, sizeof(good_full_transaction));
	generated_transaction[sizeof(good_full_transaction)] = 0xca;
	testTransaction(generated_transaction, length, "junkatend", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	length = sizeof(good_full_transaction) + 65537;
	generated_transaction = malloc(length);

	memcpy(generated_transaction, good_full_transaction, sizeof(good_full_transaction));
	memset(&(generated_transaction[sizeof(good_full_transaction)]), 3, 65537);
	testTransaction(generated_transaction, length, "junkatend2", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	/*
	 * Check that the signature hash is a double SHA-256 hash of the
	 * (main) transaction. This doesn't test if the signature hash is Bitcoin
	 * compatible. The easiest way to check if the signature hash is Bitcoin
	 * compatible is to sign a transaction and see if other nodes relay it.
	 */
	 printf("Check that the signature hash is a double SHA-256 hash of the (main) transaction\n");

	setTestInputStream(good_full_transaction, sizeof(good_full_transaction));
	parseTransaction(sig_hash, transaction_hash, sizeof(good_full_transaction));

	sha256BeginTZ(1);

	sha256WriteTZ((uint8_t*)good_main_transaction, (uint32_t)sizeof(good_main_transaction), 1);

	sha256FinishDoubleTZ(test_hs, (uint32_t)32, 1);

	writeHashToByteArrayTZ(calculated_sig_hash, test_hs, false);

	if (memcmp(calculated_sig_hash, sig_hash, 32))
	{
		printf("parseTransaction() isn't calculating signature hash properly\n");
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();

	/*
	 * Check that the transaction hash is a double SHA-256 of the (main)
	 * transaction, ignoring input scripts.
	 */
	printf("Check that the transaction hash is a double SHA-256 of the (main) transaction, ignoring input scripts\n");

	//sha256Begin(&test_hs);

	sha256BeginTZ(1);

	// for (i = 0; i < (int)sizeof(good_main_transaction); i++)
	// {
	// 	if (i == 41)
	// 		i += 26;	/* Skip input script */

	// 	//sha256WriteByte(&test_hs, good_main_transaction[i]);
	// 	sha256WriteTZ((uint8_t*)&(good_main_transaction[i]), (uint32_t)1);
	// }

	sha256WriteTZ((uint8_t*)good_main_transaction, (uint32_t)41, 1);
	sha256WriteTZ((uint8_t*)&(good_main_transaction[67]), 81, 1);


	//sha256FinishDouble(&test_hs);
	sha256FinishDoubleTZ(test_hs, (uint32_t)32, 1);

	//writeHashToByteArray(calculated_transaction_hash, &test_hs, false);

	writeHashToByteArrayTZ(calculated_transaction_hash, test_hs, false);

	if (memcmp(calculated_transaction_hash, transaction_hash, 32))
	{
		printf("parseTransaction() isn't calculating transaction hash properly\n");
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();

	/*
	 * Now change one byte in the input script. The signature hash should
	 * change, but the transaction hash should not.
	 */
	printf("Now change one byte in the input script. The signature hash should change, but the transaction hash should not.\n");

	memcpy(bad_full_transaction, good_full_transaction, sizeof(good_full_transaction));

	bad_full_transaction[305] = 0x04;	/* First byte of input script */

	setTestInputStream(bad_full_transaction, sizeof(good_full_transaction));

	parseTransaction(sig_hash_input_changed, transaction_hash_input_changed, sizeof(good_full_transaction));

	if (!memcmp(sig_hash_input_changed, sig_hash, 32))
	{
		printf("Signature hash doesn't change when input script changes\n");
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();

	if (memcmp(transaction_hash_input_changed, transaction_hash, 32))
	{
		printf("Transaction hash changes when input script changes\n");
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();

	/*
	 * As a sanity check, change one byte in an output script. Both the
	 * signature and transaction hashes should change.
	 */
	printf("As a sanity check, change one byte in an output script. Both the signature and transaction hashes should change\n");

	memcpy(bad_full_transaction, good_full_transaction, sizeof(good_full_transaction));

	bad_full_transaction[366] = 0x00;	/* Last byte of output address */

	setTestInputStream(bad_full_transaction, sizeof(good_full_transaction));

	parseTransaction(sig_hash_output_changed, transaction_hash_output_changed, sizeof(good_full_transaction));

	if (!memcmp(sig_hash_output_changed, sig_hash, 32))
	{
		printf("Signature hash doesn't change when output script changes\n");
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();

	if (!memcmp(transaction_hash_output_changed, transaction_hash, 32))
	{
		printf("Transaction hash doesn't change when output script changes\n");
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();

	/*
	 * Check that the transaction parser doesn't choke on a transaction
	 * with the maximum possible size. This test takes a while.
	 */
	printf("Check that the transaction parser doesn't choke on a transaction with the maximum possible size. This test takes a while\n");

	testTransaction(NULL, 0xffffffff, "max_size", TRANSACTION_TOO_LARGE);

	/* Go through encapsulateSignature() tests. */
	printf("Go through encapsulateSignature() tests\n");

	num_tests = sizeof(encapsulate_tests) / sizeof(struct EncapsulateSignatureTestStruct);

	for (i = 0; i < num_tests; i++)
	{
		signature_length = encapsulateSignature(signature, (uint8_t *)(encapsulate_tests[i].r), (uint8_t *)(encapsulate_tests[i].s));

		if (signature_length != encapsulate_tests[i].expected_length)
		{
			printf("Signature length mismatch on encapsulateSignature() test %d\n", i);
			reportFailureTransaction();
		}
		else
		{
			if (memcmp(signature, encapsulate_tests[i].expected_signature, signature_length))
			{
				printf("Signature contents mismatch on encapsulateSignature() test %d\n", i);
				reportFailureTransaction();
			}
			else
				reportSuccessTransaction();
		}
	}

	/* Check that signTransaction() actually writes to the signature buffer and signature length. */
	printf(" Check that signTransaction() actually writes to the signature buffer and signature length\n");

	memset(signature, 0, sizeof(signature));
	memset(&signature_length, 0, sizeof(signature_length));
	memset(sig_hash, 42, 32);

	signTransaction(signature, &signature_length, sig_hash, (BigNum256)private_key);

	if ((signature[0] != 0x30)|| (signature_length == 0))
	{
		printf("signTransaction() isn't writing to its outputs\n");
		reportFailureTransaction();
	}
	else
		reportSuccessTransaction();

	finaliseTestsTransaction();

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}