/** \file
  *
  * \brief TO DO YET!!!!
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "bignum256.h"
#include "common.h"
#include "ecdsa.h"
#include "endian.h"
#include "extern.h"
#include "prandom.h"
#include "storage_common.h"
#include "test_helpers.h"
#include "test_prandom.h"
#include "tz_functions.h"

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

void reportFailurePrandom(void)
{
	tests_failed++;
	tests_total++;
	printf("\tTest %2d: FAILED\n", tests_total);
}

void reportSuccessPrandom(void)
{
	tests_passed++;
	tests_total++;
	printf("\tTest %2d: PASSED\n", tests_total);
}

/** Test whether deterministic key generator is a type-2 generator. This means
  * that CKD(x, n) * G = CKD'(x * G, n) i.e. public keys can be derived
  * without knowing the parent private key.
  * \param seed generateDeterministic256().
  * \param num See generateDeterministic256().
  */
static void type2DeterministicTest(uint8_t *seed, uint32_t num)
{
	uint8_t private_key[32];
	PointAffine compare_public_key;
	PointAffine other_parent_public_key;
	PointAffine public_key;

	/* Calculate CKD(x, n) * G. */
	clearParentPublicKeyCache();	/* ensure public key cache has been cleared */

	assert(!generateDeterministic256(private_key, seed, num));

	setToGTestTZ(&compare_public_key);

	pointMultiplyTestTZ(&compare_public_key, private_key);

	/* Calculate CKD'(x * G, n). */
	memcpy(private_key, seed, 32);

	swapEndian256(private_key);

	setToGTestTZ(&other_parent_public_key);

	pointMultiplyTestTZ(&other_parent_public_key, private_key);

	generateDeterministicPublicKey(&public_key, &other_parent_public_key, &(seed[32]), num);

	/* Compare them. */
	if (memcmp(&compare_public_key, &public_key, sizeof(PointAffine)))
	{
		printf("Determinstic key generator is not type-2, num = %u\n", num);

		printf("Parent private key: ");
		printBigEndian16(seed);

		printf("\nChain code: ");
		printBigEndian16(&(seed[32]));
		printf("\n");

		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();
}

void initialiseTestsPrandom(void)
{
	is_test = true;
	is_test_prandom = true;

	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	srand(42);	/* Make sure tests which rely on rand() are deterministic */

	printf("\n\n=====================================================================================================================================================\n");

	printf("Initializing the wallet storage ... ");
	createWalletStorage();
	openWalletStorage();
	printf("done\n");

	printf("Executing the tests for prandom now.\n");

	printf("=====================================================================================================================================================\n");

	start_time = clock();
}

void finaliseTestsPrandom(void)
{
	time_t t;

	finish_time = clock();

	is_test = false;
	is_test_prandom = false;

	broken_hwrng = false;

	time_spent = ((double) (finish_time - start_time)) / CLOCKS_PER_SEC;

	closeWalletStorage();
	deleteWalletStorage();

	srand((unsigned) time(&t));

	printf("\n=====================================================================================================================================================\n");

	printf("Finished executing the tests for prandom\n\n");

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	printf("=====================================================================================================================================================\n\n");
}

void TestPrandom(statistics * stats)
{
	bool abort;
	uint8_t seed[SEED_LENGTH];
	uint8_t keys[SEED_LENGTH][32];
	uint8_t key2[32];
	PointAffine public_key;
	uint8_t public_key_binary[65];
	uint8_t pool_state[ENTROPY_POOL_LENGTH];
	uint8_t compare_pool_state[ENTROPY_POOL_LENGTH];
	uint8_t one_byte;
	uint8_t one_byte_corrupted;
	int i, j;
	uint8_t generated_using_nv[1024];
	uint8_t generated_using_ram[1024];
	char otp[OTP_LENGTH];
	char otp2[OTP_LENGTH];

	initialiseTestsPrandom();

	broken_hwrng = false;

	/*
	 * Before outputting samples, do a sanity check that
	 * generateDeterministic256() actually has different outputs when
	 * each byte of the seed is changed.
	 */

	printf("Sanity check\n");

	abort = false;

	for (i = 0; i < SEED_LENGTH; i++)
	{
		memset(seed, 42, SEED_LENGTH);	/* Seed cannot be all 0 */

		seed[i] = 1;

		clearParentPublicKeyCache(); 	/* Ensure public key cache has been cleared */

		assert(!generateDeterministic256(keys[i], seed, 0));

		for (j = 0; j < i; j++)
		{
			if (bigCompare(keys[i], keys[j]) == BIGCMP_EQUAL)
			{
				printf("generateDeterministic256() is ignoring byte %d of seed\n", i);
				abort = true;
				break;
			}
		}

		if (abort)
			break;
	}

	if (abort)
		reportFailurePrandom();
	else
		reportSuccessPrandom();

	/* Check that generateDeterministic256() isn't ignoring num. */
	printf("Check that generateDeterministic256() isn't ignoring num\n");

	memset(seed, 42, SEED_LENGTH);	/* Seed cannot be all 0 */

	seed[0] = 1;

	clearParentPublicKeyCache();	/* Ensure public key cache has been cleared */

	assert(!generateDeterministic256(key2, seed, 1));

	abort = false;

	for (j = 0; j < SEED_LENGTH; j++)
	{
		if (bigCompare(key2, keys[j]) == BIGCMP_EQUAL)
		{
			printf("generateDeterministic256() is ignoring num\n");
			abort = true;
			break;
		}
	}

	if (abort)
		reportFailurePrandom();
	else
		reportSuccessPrandom();

	/* Check that generateDeterministic256() is actually deterministic. */
	printf("Check that generateDeterministic256() is actually deterministic\n");

	clearParentPublicKeyCache();	/* Ensure public key cache has been cleared */

	assert(!generateDeterministic256(key2, seed, 0));

	if (bigCompare(key2, keys[0]) != BIGCMP_EQUAL)
	{
		printf("generateDeterministic256() is not deterministic\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom(),

	/* Check that generateDeterministic256() generates BIP 0032 private keys correctly. */
	printf("Check that generateDeterministic256() generates BIP 0032 private keys correctly\n");

	memcpy(seed, sipa_test_master_seed, SEED_LENGTH);

	for (i = 1; i < SIPA_TEST_ADDRESSES; i++)
	{
		clearParentPublicKeyCache();	/* Ensure public key cache has been cleared */

		assert(!generateDeterministic256TestTZ(key2, seed, (uint32_t)0x12345678));

		/*
		 * GenerateDeterministic256() generates private keys, but the test
		 * vectors include only derived public keys, so the generated private
		 * keys need to be converted into public keys.
		 */
		setToGTestTZ(&public_key);

		pointMultiplyTestTZ(&public_key, key2);

		swapEndian256(public_key.x);
		swapEndian256(public_key.y);

		/* Compare generated public keys with test vectors. */
		public_key_binary[0] = 0x04;

		memcpy(&(public_key_binary[1]), public_key.x, 32);
		memcpy(&(public_key_binary[33]), public_key.y, 32);
		if (public_key.is_point_at_infinity || memcmp(public_key_binary, sipa_test_public_keys[i], sizeof(public_key_binary)))
		{
			printf("generateDeterministic256() failed sipa test %d\n", i);
			reportFailurePrandom();
		}
		else
			reportSuccessPrandom();

		/* Get derived seed. */
		memcpy(seed, key2, 32);

		swapEndian256(seed);

		memcpy(&(seed[32]), test_chain_code, sizeof(test_chain_code));
	}

	/* Check that generateDeterministic256() functions as a type-2 deterministic wallet i.e. CKD(x, n) * G = CKD'(x * G, n). */
	printf("Check that generateDeterministic256() functions as a type-2 deterministic wallet\n");
	for (i = 0; i < 2; i++)
	{
		/* Try two different seeds. */
		if (i == 0)
		{
			memset(seed, 42, SEED_LENGTH);
			seed[2] = 1;
		}
		else
			memcpy(seed, sipa_test_master_seed, SEED_LENGTH);

		type2DeterministicTest(seed, 0);
		type2DeterministicTest(seed, 1);
		type2DeterministicTest(seed, 0xfffffffe);
		type2DeterministicTest(seed, 4095);
		type2DeterministicTest(seed, 0xffffffff);
	}

	/* Test if setEntropyPool() works. */
	printf("Test if setEntropyPool() works\n");

	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
		pool_state[i] = (uint8_t)(rand() & 0xff);

	if (setEntropyPool(pool_state))
	{
		printf("setEntropyPool() doesn't work\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	/* Check that getEntropyPool() returns what was set using setEntropyPool(). */
	printf("Check that getEntropyPool() returns what was set using setEntropyPool()\n");

	if (getEntropyPool(compare_pool_state))
	{
		printf("getEntropyPool() doesn't work\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	if (memcmp(pool_state, compare_pool_state, ENTROPY_POOL_LENGTH))
	{
		printf("getEntropyPool() doesn't return what was set using setEntropyPool()\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	/* Check that the checksum actually detects modification of the entropy pool */
	printf("Check that the checksum actually detects modification of the entropy pool\n");

	abort = false;

	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		nonVolatileRead(&one_byte, PARTITION_GLOBAL, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1);	/* Save */

		one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);

		nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1);

		if (!getEntropyPool(pool_state))
		{
			printf("getEntropyPool() not detecting corruption at i = %d\n", i);
			reportFailurePrandom();
			abort = true;
			break;
		}

		nonVolatileWrite(&one_byte, PARTITION_GLOBAL, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1); // restore
	}

	if (!abort)
		reportSuccessPrandom();


	/* Check that the checksum actually detects modification of the checksum itself. */
	printf("Check that the checksum actually detects modification of the checksum itself\n");

	abort = false;

	for (i = 0; i < POOL_CHECKSUM_LENGTH; i++)
	{
		nonVolatileRead(&one_byte,PARTITION_GLOBAL,  (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1);	/* Save */

		one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);

		nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1);

		if (!getEntropyPool(pool_state))
		{
			printf("getEntropyPool() not detecting corruption at i = %d\n", i);
			reportFailurePrandom();
			abort = true;
			break;
		}

		nonVolatileWrite(&one_byte, PARTITION_GLOBAL, (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1); // restore
	}

	if (!abort)
		reportSuccessPrandom();

	/*
	 * With a known initial pool state and with a broken HWRNG, the random
	 * number generator should produce the same output whether the pool is
	 * stored in non-volatile memory or RAM.
	 */
	printf("Check pool state with broken HWRNG\n");

	broken_hwrng = true;

	memset(pool_state, 42, ENTROPY_POOL_LENGTH);

	setEntropyPool(pool_state);

	for (i = 0; i < (int)sizeof(generated_using_nv); i += 32)
	{
		if (getRandom256(&(generated_using_nv[i])))
		{
			printf("Unexpected failure of getRandom256()\n");
			exit(1);
		}
	}

	memset(pool_state, 42, ENTROPY_POOL_LENGTH);

	for (i = 0; i < (int)sizeof(generated_using_ram); i += 32)
	{
		if (getRandom256TemporaryPool(&(generated_using_ram[i]), pool_state))
		{
			printf("Unexpected failure of getRandom256()\n");
			exit(1);
		}
	}

	if (memcmp(generated_using_nv, generated_using_ram, sizeof(generated_using_nv)))
	{
		printf("getRandom256() acts differently when using different places to store the entropy pool\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	/* initialiseEntropyPool() should directly set the entropy pool state if the current state is invalid. */
	printf("initialiseEntropyPool() should directly set the entropy pool state if the current state is invalid\n");

	memset(pool_state, 0, ENTROPY_POOL_LENGTH);

	setEntropyPool(pool_state);	/* Make sure entropy pool state is valid before corrupting it */

	nonVolatileRead(&one_byte, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);

	one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);

	nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);

	memset(pool_state, 43, ENTROPY_POOL_LENGTH);

	if (initialiseEntropyPool(pool_state))
	{
		printf("initialiseEntropyPool() doesn't work\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	getEntropyPool(compare_pool_state);

	if (memcmp(pool_state, compare_pool_state, ENTROPY_POOL_LENGTH))
	{
		printf("initialiseEntropyPool() not setting pool state when current one is invalid\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	/* initialiseEntropyPool() should mix in the specified entropy pool state if the current state is valid.*/
	printf("initialiseEntropyPool() should mix in the specified entropy pool state if the current state is valid\n");

	memset(pool_state, 42, ENTROPY_POOL_LENGTH);

	setEntropyPool(pool_state);	/* Make sure entropy pool state is valid */

	memset(pool_state, 43, ENTROPY_POOL_LENGTH);

	initialiseEntropyPool(pool_state);

	getEntropyPool(compare_pool_state);

	if (!memcmp(pool_state, compare_pool_state, ENTROPY_POOL_LENGTH))
	{
		printf("initialiseEntropyPool() not mixing pool state when current one is valid\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	/* Check that generateInsecureOTP() passwords are actually one-time. */
	printf("Check that generateInsecureOTP() passwords are actually one-time\n");

	broken_hwrng = false;

	generateInsecureOTP(otp);
	generateInsecureOTP(otp2);

	if (!memcmp(otp, otp2, sizeof(otp)))
	{
		printf("generateInsecureOTP() passwords are not one-time\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	/* Check that generateInsecureOTP() still works when the entropy pool is corrupted. */
	printf("Check that generateInsecureOTP() still works when the entropy pool is corrupted\n");

	nonVolatileRead(&one_byte, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);

	one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);

	nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);

	generateInsecureOTP(otp);

	generateInsecureOTP(otp2);

	if (!memcmp(otp, otp2, sizeof(otp)))
	{
		printf("generateInsecureOTP() doesn't work when entropy pool is borked\n");
		reportFailurePrandom();
	}
	else
		reportSuccessPrandom();

	finaliseTestsPrandom();

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}
