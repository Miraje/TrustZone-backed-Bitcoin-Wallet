/** \file
  *
  * \brief TO DO YET!!!!
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "bignum256.h"
#include "ecdsa.h"
#include "endian.h"
#include "extern.h"
#include "prandom.h"
#include "storage_common.h"
#include "test_helpers.h"
#include "test_wallet.h"
#include "tz_functions.h"
#include "wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/** This is only used as a testing variable  */
WalletRecord test_wallet;

int tests_passed;
int tests_failed;
int tests_total;
clock_t start_time;
clock_t finish_time;
double time_spent;

const uint8_t test_password0[] = "1234";
const uint8_t test_password1[] = "ABCDEFGHJ!!!!";
const uint8_t new_test_password[] = "new password";

void reportFailureWallet(void)
{
	tests_failed++;
	tests_total++;
	printf("\tTest %2d: FAILED\n", tests_total);
}

void reportSuccessWallet(void)
{
	tests_passed++;
	tests_total++;
	printf("\tTest %2d: PASSED\n", tests_total);
}

/** This will be called by sanitiseNonVolatileStorage() every time it
  * clears the version field of a wallet. This is used to test whether
  * sanitiseNonVolatileStorage() is clearing version fields properly.
  * \param address The address (in non-volatile storage) where the cleared
  *                version field is.
  */
void logVersionFieldWrite(uint32_t address)
{
    if (version_field_index < (int)(sizeof(version_field_writes) / sizeof(uint32_t)))
        version_field_writes[version_field_index++] = address;
}

/** Clear the list of version field writes. */
void clearVersionFieldWriteLog(void)
{
    version_field_index = 0;
}

/** Call all wallet functions which accept a wallet number and check
  * that they fail or succeed for a given wallet number.
  * \param wallet_spec The wallet number to check.
  * \param should_succeed true if the wallet number is valid (and thus the
  *                       wallet functions should succeed), false if the wallet
  *                       number is not valid (and thus the wallet functions
  *                       should fail).
  */
static void checkWalletSpecFunctions(uint32_t wallet_spec, bool should_succeed)
{
	uint8_t wallet_uuid[UUID_LENGTH];
	uint8_t name[NAME_LENGTH];
	uint32_t version;
	WalletErrors wallet_return;

	memset(name, ' ', NAME_LENGTH);

	uninitWallet();

	wallet_return = newWallet(wallet_spec, name, false, NULL, false, NULL, 0);

	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("newWallet() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("newWallet() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	/*
	 * This call to initWallet() must be placed after the call to newWallet()
	 * so that if should_succeed is true, there's a valid wallet in the
	 * specified place.
	 */
	wallet_return = initWallet(wallet_spec, NULL, 0);

	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("initWallet() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("initWallet() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	wallet_return = getWalletInfo(&version, name, wallet_uuid, wallet_spec);

	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("getWalletInfo() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailureWallet();
	}
	else
		reportSuccessWallet();
	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("getWalletInfo() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailureWallet();
	}
	else
		reportSuccessWallet();
}

/** Call nearly all wallet functions and make sure they
  * return #WALLET_NOT_LOADED somehow. This should only be called if a wallet
  * is not loaded. */
static void checkFunctionsReturnWalletNotLoaded(void)
{
	uint8_t temp[128];
	uint32_t check_num_addresses;
	AddressHandle ah;
	PointAffine public_key;

	/* newWallet() not tested because it calls initWallet() when it's done. */
	ah = makeNewAddress(temp, &public_key);

	if ((ah == BAD_ADDRESS_HANDLE) && (walletGetLastError() == WALLET_NOT_LOADED))
		reportSuccessWallet();
	else
	{
		printf("makeNewAddress() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}

	check_num_addresses = getNumAddresses();

	if ((check_num_addresses == 0) && (walletGetLastError() == WALLET_NOT_LOADED))
		reportSuccessWallet();
	else
	{
		printf("getNumAddresses() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}

	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_NOT_LOADED)
		reportSuccessWallet();
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}

	if (getPrivateKey(temp, 0) == WALLET_NOT_LOADED)
		reportSuccessWallet();
	else
	{
		printf("getPrivateKey() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}

	if (changeEncryptionKey(temp, 0) == WALLET_NOT_LOADED)
		reportSuccessWallet();
	else
	{
		printf("changeEncryptionKey() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}

	if (changeWalletName(temp) == WALLET_NOT_LOADED)
		reportSuccessWallet();
	else
	{
		printf("changeWalletName() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}

	if (backupWallet(false, 0) == WALLET_NOT_LOADED)
		reportSuccessWallet();
	else
	{
		printf("backupWallet() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}

	if (getMasterPublicKey(&public_key, temp) == WALLET_NOT_LOADED)
		reportSuccessWallet();
	else
	{
		printf("getMasterPublicKey() doesn't recognise when wallet isn't loaded\n");
		reportFailureWallet();
	}
}

void initialiseTestsWallet(void)
{
	is_test = true;
	is_test_wallet = true;

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

	printf("Executing the tests for wallet now.\n");

	printf("=====================================================================================================================================================\n");

	start_time = clock();
}

void finaliseTestsWallet(void)
{
	time_t t;

	finish_time = clock();

	is_test = false;
	is_test_wallet = false;
	suppress_write_debug_info = true;	/* To save some printing time for the next tests */

	time_spent = ((double) (finish_time - start_time)) / CLOCKS_PER_SEC;

	closeWalletStorage();
	deleteWalletStorage();

	srand((unsigned) time(&t));

	printf("\n=====================================================================================================================================================\n");

	printf("Finished executing the tests for wallet\n\n");

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	printf("=====================================================================================================================================================\n\n");
}

void TestWallet(statistics * stats)
{
	uint8_t temp[128];
	int i;
	uint32_t histogram[256];
	uint32_t histogram_count;
	bool abort;
	uint32_t version;
	uint8_t wallet_uuid[UUID_LENGTH];
	uint8_t name[NAME_LENGTH];
	PointAffine public_key;
	uint8_t one_byte;
	uint8_t address1[20];
	uint8_t address2[20];
	bool is_zero;
	bool abort_error;
	uint8_t *address_buffer;
	int j;
	PointAffine *public_key_buffer;
	AddressHandle *handles_buffer;
	AddressHandle ah;
	bool abort_duplicate;
	uint8_t seed1[SEED_LENGTH];
	uint8_t seed2[SEED_LENGTH];
	uint8_t encrypted_seed[SEED_LENGTH];
	uint32_t start_address;
	uint32_t end_address;
	bool found;
	uint32_t version_field_address;
	int version_field_counter;
	uint32_t stupidly_calculated_num_wallets;
	uint32_t returned_num_wallets;
	uint8_t name2[NAME_LENGTH];
	uint8_t compare_address[20];
	uint8_t compare_name[NAME_LENGTH];
	struct WalletRecordUnencryptedStruct unencrypted_part;
	struct WalletRecordUnencryptedStruct compare_unencrypted_part;
	uint8_t wallet_uuid2[UUID_LENGTH];
	uint8_t chain_code[32];
	uint8_t copy_of_nv[GLOBAL_PARTITION_SIZE + ACCOUNTS_PARTITION_SIZE];
	uint8_t copy_of_nv2[GLOBAL_PARTITION_SIZE + ACCOUNTS_PARTITION_SIZE];
	uint8_t pool_state[ENTROPY_POOL_LENGTH];
	PointAffine master_public_key;
	PointAffine compare_public_key;

	initialiseTestsWallet();

	suppress_set_entropy_pool = false;

	/* Blank out non-volatile storage area (set to all nulls). */
	temp[0] = 0;

	printf("Blanking out non-volatile storage area (setting to all nulls)\n");

	for (i = 0; i < (GLOBAL_PARTITION_SIZE + ACCOUNTS_PARTITION_SIZE); i++)
		nonVolatileWrite1Byte(temp);
		//fwrite(temp, 1, 1, wallet_storage_file);

	/* Check that sanitiseEverything() is able to function with NV storage in this state. */
	printf("Check that sanitiseEverything() is able to function with NV storage in this state\n");

	minimum_address_written[PARTITION_GLOBAL] = 0xffffffff;
	maximum_address_written[PARTITION_GLOBAL] = 0;
	minimum_address_written[PARTITION_ACCOUNTS] = 0xffffffff;
	maximum_address_written[PARTITION_ACCOUNTS] = 0;

	if (sanitiseEverything() == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Cannot nuke NV storage using sanitiseEverything()\n");
		reportFailureWallet();
	}

	/* Check that sanitiseNonVolatileStorage() overwrote (almost) everything with random data. */
	printf("Check that sanitiseNonVolatileStorage() overwrote (almost) everything with random data\n");

	memset(histogram, 0, sizeof(histogram));

	histogram_count = 0;

	seekWalletStorage(0);

	for (i = 0; i < (GLOBAL_PARTITION_SIZE + ACCOUNTS_PARTITION_SIZE); i++)
	{
		//fread(temp, 1, 1, wallet_storage_file);
		nonVolatileRead1Byte(temp);
		histogram[temp[0]]++;
		histogram_count++;
	}

	// "Random data" here is defined as: no value appears more than 1/16 of the time.
	abort = false;

	for (i = 0; i < 256; i++)
	{
		if (histogram[i] > (histogram_count / 16))
		{
			printf("sanitiseNonVolatileStorage() causes %02x to appear improbably often\n", i);
			reportFailureWallet();
			abort = true;
		}
	}

	if (!abort)
		reportSuccessWallet();

	/* Check that sanitiseEverything() overwrote everything. */
	printf("Check that sanitiseEverything() overwrote everything.\n");

	if ((minimum_address_written[PARTITION_GLOBAL] != 0)
		|| (maximum_address_written[PARTITION_GLOBAL] != (GLOBAL_PARTITION_SIZE - 1))
		|| (minimum_address_written[PARTITION_ACCOUNTS] != 0)
		|| (maximum_address_written[PARTITION_ACCOUNTS] != (ACCOUNTS_PARTITION_SIZE - 1)))
	{
		printf("sanitiseEverything() did not overwrite everything\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that the version field is "wallet not there". */
	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() failed after sanitiseNonVolatileStorage() was called\n");
		reportFailureWallet();
	}

	if (version == VERSION_NOTHING_THERE)
		reportSuccessWallet();
	else
	{
		printf("sanitiseNonVolatileStorage() does not set version to nothing there\n");
		reportFailureWallet();
	}

	/* initWallet() hasn't been called yet, so nearly every function should return WALLET_NOT_THERE somehow. */
	printf("initWallet() hasn't been called yet, so nearly every function should return WALLET_NOT_THERE somehow.\n");

	checkFunctionsReturnWalletNotLoaded();

	/* The non-volatile storage area was blanked out, so there shouldn't be a (valid) wallet there. */
	printf("The non-volatile storage area was blanked out, so there shouldn't be a (valid) wallet there.\n");

	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
		reportSuccessWallet();
	else
	{
		printf("initWallet() doesn't recognise when wallet isn't there\n");
		reportFailureWallet();
	}

	/* Try creating a wallet and testing initWallet() on it. */
	printf("Try creating a wallet and testing initWallet() on it\n");

	memcpy(name, "123456789012345678901234567890abcdefghij", NAME_LENGTH);

	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Could not create new wallet\n");
		reportFailureWallet();
	}

	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("initWallet() does not recognise new wallet\n");
		reportFailureWallet();
	}

	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
		reportSuccessWallet();
	else
	{
		printf("New wallet isn't empty\n");
		reportFailureWallet();
	}

	/* Check that the version field is "unencrypted wallet". */
	printf("Check that the version field is 'unencrypted wallet'\n");

	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() failed after newWallet() was called\n");
		reportFailureWallet();
	}

	if (version == VERSION_UNENCRYPTED)
		reportSuccessWallet();
	else
	{
		printf("newWallet() does not set version to unencrypted wallet\n");
		reportFailureWallet();
	}

	/* Check that sanitise_nv_wallet() deletes wallet. */
	printf("Check that sanitise_nv_wallet() deletes wallet\n");

	if (sanitiseEverything() == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Cannot nuke NV storage using sanitiseNonVolatileStorage()\n");
		reportFailureWallet();
	}

	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
		reportSuccessWallet();
	else
	{
		printf("sanitiseEverything() isn't deleting wallet\n");
		reportFailureWallet();
	}

	/* Check that newWallet() works. */
	printf("Check that newWallet() works\n");

	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("newWallet() fails for recently sanitised NV storage\n");
		reportFailureWallet();
	}

	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailureWallet();
	}

	/* newWallet() shouldn't overwrite an existing wallet. */
	printf("newWallet() shouldn't overwrite an existing wallet\n");

	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_ALREADY_EXISTS)
		reportSuccessWallet();
	else
	{
		printf("newWallet() overwrites existing wallet\n");
		reportFailureWallet();
	}

	/* Check that a deleteWallet()/newWallet() sequence does overwrite an existing wallet. */
	printf("Check that a deleteWallet()/newWallet() sequence does overwrite an existing wallet\n");

	if (deleteWallet(0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("deleteWallet() failed\n");
		reportFailureWallet();
	}

	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("newWallet() fails for recently deleted wallet\n");
		reportFailureWallet();
	}

	/* Check that deleteWallet() deletes wallet. */
	printf("Check that deleteWallet() deletes wallet\n");

	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);

	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("initWallet() failed just after calling newWallet()\n");
		reportFailureWallet();
	}

	deleteWallet(0);

	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
		reportSuccessWallet();
	else
	{
		printf("deleteWallet() isn't deleting wallet\n");
		reportFailureWallet();
	}

	/* Check that deleteWallet() doesn't affect other wallets. */
	printf("Check that deleteWallet() doesn't affect other wallets\n");

	deleteWallet(0);
	deleteWallet(1);

	newWallet(0, name, false, NULL, false, NULL, 0);
	newWallet(1, name, false, NULL, false, NULL, 0);

	deleteWallet(1);

	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("deleteWallet() collateral damage to wallet 0\n");
		reportFailureWallet();
	}

	deleteWallet(0);
	deleteWallet(1);

	newWallet(0, name, false, NULL, false, NULL, 0);
	newWallet(1, name, false, NULL, false, NULL, 0);

	deleteWallet(0);

	if (initWallet(1, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("deleteWallet() collateral damage to wallet 1\n");
		reportFailureWallet();
	}

	/*
	 * Make some new addresses, then delete it and create a new wallet,
	 * making sure the new wallet is empty (i.e. check that deleteWallet()
	 * actually deletes a wallet).
	 */
	printf("check that deleteWallet() actually deletes a wallet\n");

	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);

	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("Couldn't create new address in new wallet 2\n");
		reportFailureWallet();
	}

	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);

	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
		reportSuccessWallet();
	else
	{
		printf("deleteWallet() doesn't delete existing wallet\n");
		reportFailureWallet();
	}

	/* Unload wallet and make sure everything realises that the wallet is not loaded. */
	printf("Unload wallet and make sure everything realises that the wallet is not loaded\n");

	if (uninitWallet() == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("uninitWallet() failed to do its basic job\n");
		reportFailureWallet();
	}

	checkFunctionsReturnWalletNotLoaded();

	/* Load wallet again. Since there is actually a wallet there, this should succeed. */
	printf("Load wallet again. Since there is actually a wallet there, this should succeed\n");

	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("uninitWallet() appears to be permanent\n");
		reportFailureWallet();
	}

	/* Change bytes in non-volatile memory and make sure initWallet() fails because of the checksum check. */
	printf("Change bytes in non-volatile memory and make sure initWallet() fails because of the checksum check\n");

	if (uninitWallet() != WALLET_NO_ERROR)
	{
		printf("uninitWallet() failed to do its basic job 2\n");
		reportFailureWallet();
	}

	abort = false;

	for (i = 0; i < (int)sizeof(WalletRecord); i++)
	{
		if (nonVolatileRead(&one_byte, PARTITION_ACCOUNTS, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV read fail\n");
			abort = true;
			break;
		}

		one_byte++;

		if (nonVolatileWrite(&one_byte, PARTITION_ACCOUNTS, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV write fail\n");
			abort = true;
			break;
		}

		if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
		{
			printf("Wallet still loads when wallet checksum is wrong, offset = %d\n", i);
			abort = true;
			break;
		}

		one_byte--;

		if (nonVolatileWrite(&one_byte, PARTITION_ACCOUNTS, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV write fail\n");
			abort = true;
			break;
		}
	}

	if (!abort)
		reportSuccessWallet();
	else
		reportFailureWallet();

	/* deleteWallet() should succeed even if aimed at a wallet that "isn't there"; this is how hidden wallets can be deleted. */
	printf("deleteWallet() should succeed even if aimed at a wallet that isn't there\n");

	deleteWallet(0);

	if (deleteWallet(0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("deleteWallet() can't delete wallet that isn't there\n");
		reportFailureWallet();
	}

	/* Create 2 new wallets and check that their addresses aren't the same. */
	printf("Create 2 new wallets and check that their addresses aren't the same\n");

	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);

	if (makeNewAddress(address1, &public_key) != BAD_ADDRESS_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailureWallet();
	}

	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);

	memset(address2, 0, 20);

	memset(&public_key, 0, sizeof(PointAffine));

	if (makeNewAddress(address2, &public_key) != BAD_ADDRESS_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailureWallet();
	}

	if (memcmp(address1, address2, 20))
		reportSuccessWallet();
	else
	{
		printf("New wallets are creating identical addresses\n");
		reportFailureWallet();
	}

	/* Check that makeNewAddress() wrote to its outputs. */
	printf("Check that makeNewAddress() wrote to its outputs\n");

	is_zero = true;

	for (i = 0; i < 20; i++)
	{
		if (address2[i] != 0)
		{
			is_zero = false;
			break;
		}
	}

	if (is_zero)
	{
		printf("makeNewAddress() doesn't write the address\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	if (bigIsZero(public_key.x))
	{
		printf("makeNewAddress() doesn't write the public key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Make some new addresses, up to a limit. Also check that addresses are unique. */
	printf("Make some new addresses, up to a limit. Also check that addresses are unique\n");

	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);

	abort = false;

	abort_error = false;

	address_buffer = (uint8_t *)malloc(MAX_ADDRESSES * 20);

	for (i = 0; i < MAX_ADDRESSES; i++)
	{
		if (makeNewAddress(&(address_buffer[i * 20]), &public_key) == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			reportFailureWallet();
			abort_error = true;
			break;
		}

		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Wallet addresses aren't unique\n");
				reportFailureWallet();
				abort = true;
				break;
			}
		}

		if (abort || abort_error)
			break;
	}

	free(address_buffer);

	if (!abort)
		reportSuccessWallet();
	if (!abort_error)
		reportSuccessWallet();

	/* The wallet should be full now. Check that making a new address now causes an appropriate error. */
	printf("Check that making a new address now causes an appropriate error\n");

	if (makeNewAddress(temp, &public_key) == BAD_ADDRESS_HANDLE)
	{
		if (walletGetLastError() == WALLET_FULL)
			reportSuccessWallet();
		else
		{
			printf("Creating a new address on a full wallet gives incorrect error\n");
			reportFailureWallet();
		}
	}
	else
	{
		printf("Creating a new address on a full wallet succeeds (it's not supposed to)\n");
		reportFailureWallet();
	}

	/* Check that getNumAddresses() fails when the wallet is empty. */
	printf("Check that getNumAddresses() fails when the wallet is empty\n");

	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);

	if (getNumAddresses() == 0)
	{
		if (walletGetLastError() == WALLET_EMPTY)
			reportSuccessWallet();
		else
		{
			printf("getNumAddresses() doesn't recognise wallet is empty\n");
			reportFailureWallet();
		}
	}
	else
	{
		printf("getNumAddresses() succeeds when used on empty wallet\n");
		reportFailureWallet();
	}

	/* Create a bunch of addresses in the (now empty) wallet and check that getNumAddresses() returns the right number. */
	printf("Create a bunch of addresses in the (now empty) wallet and check that getNumAddresses() returns the right number\n");

	address_buffer = (uint8_t *)malloc(MAX_ADDRESSES * 20);

	public_key_buffer = (PointAffine *)malloc(MAX_ADDRESSES * sizeof(PointAffine));

	handles_buffer = (AddressHandle *)malloc(MAX_ADDRESSES * sizeof(AddressHandle));

	abort = false;

	for (i = 0; i < MAX_ADDRESSES; i++)
	{
		ah = makeNewAddress(&(address_buffer[i * 20]), &(public_key_buffer[i]));

		handles_buffer[i] = ah;

		if (ah == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			abort = true;
			reportFailureWallet();
			break;
		}
	}

	if (!abort)
		reportSuccessWallet();

	if (getNumAddresses() == MAX_ADDRESSES)
		reportSuccessWallet();
	else
	{
		printf("getNumAddresses() returns wrong number of addresses\n");
		reportFailureWallet();
	}

	/* The wallet should contain unique addresses. */
	printf("The wallet should contain unique addresses\n");

	abort_duplicate = false;

	for (i = 0; i < MAX_ADDRESSES; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Wallet has duplicate addresses\n");
				abort_duplicate = true;
				reportFailureWallet();
				break;
			}
		}

		if (abort_duplicate)
			break;
	}

	if (!abort_duplicate)
		reportSuccessWallet();

	/* The wallet should contain unique public keys. */
	printf("The wallet should contain unique public keys\n");

	abort_duplicate = false;

	for (i = 0; i < MAX_ADDRESSES; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (bigCompare(public_key_buffer[i].x, public_key_buffer[j].x) == BIGCMP_EQUAL)
			{
				printf("Wallet has duplicate public keys\n");
				abort_duplicate = true;
				reportFailureWallet();
				break;
			}
		}

		if (abort_duplicate)
			break;
	}

	if (!abort_duplicate)
		reportSuccessWallet();

	/* The address handles should start at 1 and be sequential. */
	printf("The address handles should start at 1 and be sequential\n");

	abort = false;

	for (i = 0; i < MAX_ADDRESSES; i++)
	{
		if (handles_buffer[i] != (AddressHandle)(i + 1))
		{
			printf("Address handle %d should be %d, but got %d\n", i, i + 1, (int)handles_buffer[i]);
			abort = true;
			reportFailureWallet();
			break;
		}
	}

	if (!abort)
		reportSuccessWallet();

	/*
	 * While there's a bunch of addresses in the wallet, check that
	 * getAddressAndPublicKey() obtains the same address and public key as
	 * makeNewAddress().
	 */
	printf("check that getAddressAndPublicKey() obtains the same address and public key as makeNewAddress()\n");

	abort_error = false;
	abort = false;

	for (i = 0; i < MAX_ADDRESSES; i++)
	{
		ah = handles_buffer[i];

		if (getAddressAndPublicKey(address1, &public_key, ah) != WALLET_NO_ERROR)
		{
			printf("Couldn't obtain address in wallet\n");
			abort_error = true;
			reportFailureWallet();
			break;
		}

		if ((memcmp(address1, &(address_buffer[i * 20]), 20))
			|| (bigCompare(public_key.x, public_key_buffer[i].x) != BIGCMP_EQUAL)
			|| (bigCompare(public_key.y, public_key_buffer[i].y) != BIGCMP_EQUAL))
		{
			printf("getAddressAndPublicKey() returned mismatching address or public key, ah = %d\n", i);
			abort = true;
			reportFailureWallet();
			break;
		}
	}

	if (!abort)
		reportSuccessWallet();

	if (!abort_error)
		reportSuccessWallet();

	/* Test getAddressAndPublicKey() and getPrivateKey() functions using invalid and then valid address handles. */
	printf("Test getAddressAndPublicKey() and getPrivateKey() functions using invalid and then valid address handles\n");

	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_INVALID_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise 0 as invalid address handle\n");
		reportFailureWallet();
	}

	if (getPrivateKey(temp, 0) == WALLET_INVALID_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("getPrivateKey() doesn't recognise 0 as invalid address handle\n");
		reportFailureWallet();
	}

	if (getAddressAndPublicKey(temp, &public_key, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		reportFailureWallet();
	}

	if (getPrivateKey(temp, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
		reportSuccessWallet();
	else
	{
		printf("getPrivateKey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		reportFailureWallet();
	}

	if (getAddressAndPublicKey(temp, &public_key, handles_buffer[0]) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise valid address handle\n");
		reportFailureWallet();
	}

	if (getPrivateKey(temp, handles_buffer[0]) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("getPrivateKey() doesn't recognise valid address handle\n");
		reportFailureWallet();
	}

	free(address_buffer);
	free(public_key_buffer);
	free(handles_buffer);

	/* Check that changeEncryptionKey() works. */
	printf("Check that changeEncryptionKey() works\n");

	if (changeEncryptionKey(new_test_password, sizeof(new_test_password)) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Couldn't change encryption key\n");
		reportFailureWallet();
	}

	/* Check that the version field is "encrypted wallet". */
	printf("Check that the version field is encrypted wallet\n");

	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() failed after changeEncryptionKey() was called\n");
		reportFailureWallet();
	}

	if (version == VERSION_IS_ENCRYPTED)
		reportSuccessWallet();
	else
	{
		printf("changeEncryptionKey() does not set version to encrypted wallet\n");
		reportFailureWallet();
	}

	/* Check name matches what was given in newWallet(). */
	printf("Check name matches what was given in newWallet()\n");

	if (!memcmp(temp, name, NAME_LENGTH))
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() doesn't return correct name when wallet is loaded\n");
		reportFailureWallet();
	}

	/* Check that getWalletInfo() still works after unloading wallet. */
	printf("Check that getWalletInfo() still works after unloading wallet\n");

	uninitWallet();

	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() failed after uninitWallet() was called\n");
		reportFailureWallet();
	}

	if (version == VERSION_IS_ENCRYPTED)
		reportSuccessWallet();
	else
	{
		printf("uninitWallet() caused wallet version to change\n");
		reportFailureWallet();
	}

	/* Check name matches what was given in newWallet(). */
	printf("Check name matches what was given in newWallet()\n");

	if (!memcmp(temp, name, NAME_LENGTH))
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() doesn't return correct name when wallet is not loaded\n");
		reportFailureWallet();
	}

	/* Change wallet's name and check that getWalletInfo() reflects the name change. */
	printf("Change wallet's name and check that getWalletInfo() reflects the name change\n");

	initWallet(0, new_test_password, sizeof(new_test_password));

	memcpy(name, "HHHHH HHHHHHHHHHHHHHHHH HHHHHHHHHHHHHH  ", NAME_LENGTH);

	if (changeWalletName(name) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("changeWalletName() couldn't change name\n");
		reportFailureWallet();
	}

	getWalletInfo(&version, temp, wallet_uuid, 0);

	if (!memcmp(temp, name, NAME_LENGTH))
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() doesn't reflect name change\n");
		reportFailureWallet();
	}

	/* Check that name change is preserved when unloading and loading a wallet. */
	printf("Check that name change is preserved when unloading and loading a wallet\n");

	uninitWallet();
	getWalletInfo(&version, temp, wallet_uuid, 0);

	if (!memcmp(temp, name, NAME_LENGTH))
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() doesn't reflect name change after unloading wallet\n");
		reportFailureWallet();
	}

	/*
	 * Check that initWallet() succeeds (changing the name changes the
	 * checksum, so this tests whether the checksum was updated).
	 */
	printf("Check that initWallet() succeeds (whether the checksum was updated)\n");

	if (initWallet(0, new_test_password, sizeof(new_test_password)) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("initWallet() failed after name change\n");
		reportFailureWallet();
	}

	getWalletInfo(&version, temp, wallet_uuid, 0);

	if (!memcmp(temp, name, NAME_LENGTH))
		reportSuccessWallet();
	else
	{
		printf("getWalletInfo() doesn't reflect name change after reloading wallet\n");
		reportFailureWallet();
	}

	/* Check that loading the wallet with the old key fails. */
	printf("Check that loading the wallet with the old key fails\n");

	uninitWallet();

	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
		reportSuccessWallet();
	else
	{
		printf("Loading wallet with old encryption key succeeds\n");
		reportFailureWallet();
	}

	/* Check that loading the wallet with the new key succeeds. */
	printf("Check that loading the wallet with the new key succeeds\n");

	uninitWallet();

	if (initWallet(0, new_test_password, sizeof(new_test_password)) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Loading wallet with new encryption key fails\n");
		reportFailureWallet();
	}

	/* Test the getAddressAndPublicKey() and getPrivateKey() functions on an empty wallet. */
	printf("Test the getAddressAndPublicKey() and getPrivateKey() functions on an empty wallet.\n");

	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);

	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_EMPTY)
		reportSuccessWallet();
	else
	{
		printf("getAddressAndPublicKey() doesn't deal with empty wallets correctly\n");
		reportFailureWallet();
	}

	if (getPrivateKey(temp, 0) == WALLET_EMPTY)
		reportSuccessWallet();
	else
	{
		printf("getPrivateKey() doesn't deal with empty wallets correctly\n");
		reportFailureWallet();
	}

	/* Test wallet backup to valid device. */
	printf("Test wallet backup to valid device\n");

	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);

	if (backupWallet(false, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Unencrypted backupWallet() doesn't work\n");
		reportFailureWallet();
	}

	memcpy(seed1, test_wallet_backup, SEED_LENGTH);
	makeNewAddress(address1, &public_key);	/* Save this for later */

	/* Test wallet backup to invalid device. */
	printf("Test wallet backup to invalid device\n");

	if (backupWallet(false, 1) == WALLET_BACKUP_ERROR)
		reportSuccessWallet();
	else
	{
		printf("backupWallet() doesn't deal with invalid device correctly\n");
		reportFailureWallet();
	}

	/* Delete wallet and check that seed of a new wallet is different. */
	printf("Delete wallet and check that seed of a new wallet is different\n");

	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);

	backupWallet(false, 0);
	memcpy(seed2, test_wallet_backup, SEED_LENGTH);

	if (memcmp(seed1, seed2, SEED_LENGTH))
		reportSuccessWallet();
	else
	{
		printf("Seed of new wallet matches older one.\n");
		reportFailureWallet();
	}

	/* Try to restore a wallet backup. */
	printf("Try to restore a wallet backup\n");

	deleteWallet(0);

	if (newWallet(0, name, true, seed1, false, test_password0, sizeof(test_password0)) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Could not restore wallet\n");
		reportFailureWallet();
	}

	/* Does the first address of the restored wallet match the old wallet? */
	printf("Does the first address of the restored wallet match the old wallet?\n");

	makeNewAddress(address2, &public_key);

	if (!memcmp(address1, address2, 20))
		reportSuccessWallet();
	else
	{
		printf("Restored wallet doesn't generate the same address\n");
		reportFailureWallet();
	}

	/* Test wallet backup with encryption. */
	printf("Test wallet backup with encryption\n");

	if (backupWallet(true, 0) == WALLET_NO_ERROR)
		reportSuccessWallet();
	else
	{
		printf("Encrypted backupWallet() doesn't work\n");
		reportFailureWallet();
	}

	memcpy(encrypted_seed, test_wallet_backup, SEED_LENGTH);

	/* Decrypt the encrypted seed and check it matches the unencrypted one. */
	printf("Decrypt the encrypted seed and check it matches the unencrypted one\n");

	memset(temp, 0, 16);

	aesXTS(1, encrypted_seed, SEED_LENGTH, seed2, SEED_LENGTH);

	if (!memcmp(seed1, seed2, SEED_LENGTH))
		reportSuccessWallet();
	else
	{
		printf("Decrypted seed does not match encrypted one.\n");
		reportFailureWallet();
	}

	/* Test that sanitiseNonVolatileStorage() doesn't accept addresses which aren't a multiple of 4. */
	printf("Test that sanitiseNonVolatileStorage() doesn't accept addresses which aren't a multiple of 4\n");

	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 1, 16) == WALLET_BAD_ADDRESS)
		reportSuccessWallet();
	else
	{
		printf("sanitiseNonVolatileStorage() accepts start address which is not a multiple of 4\n");
		reportFailureWallet();
	}

	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 0, 15) == WALLET_BAD_ADDRESS)
		reportSuccessWallet();
	else
	{
		printf("sanitiseNonVolatileStorage() accepts length which is not a multiple of 4\n");
		reportFailureWallet();
	}

	/* Test that sanitiseNonVolatileStorage() detects possible overflows. */
	printf("Test that sanitiseNonVolatileStorage() detects possible overflows\n");

	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 0x80000000, 0x80000000) == WALLET_BAD_ADDRESS)
		reportSuccessWallet();
	else
	{
		printf("sanitiseNonVolatileStorage() not detecting overflow 1\n");
		reportFailureWallet();
	}

	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 0xffffffff, 1) == WALLET_BAD_ADDRESS)
		reportSuccessWallet();
	else
	{
		printf("sanitiseNonVolatileStorage() not detecting overflow 2\n");
		reportFailureWallet();
	}

	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 1, 0xffffffff) == WALLET_BAD_ADDRESS)
		reportSuccessWallet();
	else
	{
		printf("sanitiseNonVolatileStorage() not detecting overflow 3\n");
		reportFailureWallet();
	}

	/*
	 * Test that sanitiseNonVolatileStorage() clears the correct area.
	 * Previously, sanitiseNonVolatileStorage() required the start and end
	 * parameters to be a multiple of 32 (because it uses a write buffer
	 * with that length). That restriction has since been relaxed. This test
	 * case checks that the code handles non-multiples of 32 properly.
	 */
	printf("Test that sanitiseNonVolatileStorage() clears the correct area\n");

	suppress_write_debug_info = true;	/* Stop console from going crazy */
	suppress_set_entropy_pool = true;	/* Avoid spurious entropy pool update writes */

	abort = false;

	//for (i = 0; i < 2000; i++)
	for (i = 0; i < 50; i++)
	{
		initialiseDefaultEntropyPool();	/* Needed in case pool or checksum gets corrupted by writes */

		minimum_address_written[PARTITION_ACCOUNTS] = 0xffffffff;
		maximum_address_written[PARTITION_ACCOUNTS] = 0;

		start_address = (uint32_t)((rand() % ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);
		end_address = start_address + (uint32_t)((rand() % ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);

		if (end_address > ACCOUNTS_PARTITION_SIZE)
			end_address = ACCOUNTS_PARTITION_SIZE;

		if (start_address != end_address)
		{
			sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, start_address, end_address - start_address);

			if ((minimum_address_written[PARTITION_ACCOUNTS] != start_address)
				|| (maximum_address_written[PARTITION_ACCOUNTS] != (end_address - 1)))
			{
				printf("sanitiseNonVolatileStorage() not clearing correct area\n");
				printf("start = 0x%08x, end = 0x%08x\n", start_address, end_address);
				abort = true;
				reportFailureWallet();
				break;
			}
		}
	}

	if (!abort)
		reportSuccessWallet();

	/* Also check that sanitiseNonVolatileStorage() does nothing if length is 0. */
	printf("Also check that sanitiseNonVolatileStorage() does nothing if length is 0\n");

	initialiseDefaultEntropyPool();	/* Needed in case pool or checksum gets corrupted by writes */

	minimum_address_written[PARTITION_ACCOUNTS] = 0xffffffff;
	maximum_address_written[PARTITION_ACCOUNTS] = 0;

	/* Use offsetof(WalletRecord, unencrypted.version) to try and trick the "clear version field" logic. */
	start_address = offsetof(WalletRecord, unencrypted.version);

	sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, start_address, 0);

	if ((minimum_address_written[PARTITION_ACCOUNTS] != 0xffffffff) || (maximum_address_written[PARTITION_ACCOUNTS] != 0))
	{
		printf("sanitiseNonVolatileStorage() clearing something when it's not supposed to\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that sanitiseNonVolatileStorage() is clearing the correct version fields of any wallets in range. */
	printf("Check that sanitiseNonVolatileStorage() is clearing the correct version fields of any wallets in range\n");

	suppress_write_debug_info = true;	/* Stop console from going crazy */
	suppress_set_entropy_pool = false;
	abort = false;

	//for (i = 0; i < 5000; i++)
	for (i = 0; i < 50; i++)
	{
		start_address = (uint32_t)((rand() % ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);
		end_address = start_address + (uint32_t)((rand() % ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);

		if (end_address > ACCOUNTS_PARTITION_SIZE)
			end_address = ACCOUNTS_PARTITION_SIZE;

		initialiseDefaultEntropyPool();	/* Needed in case pool or checksum gets corrupted by writes */
		clearVersionFieldWriteLog();
		sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, start_address, end_address - start_address);

		/*
		 * version_field_address is stepped through every possible address
		 * (ignoring start_address and end_address) that could hold a wallet's
		 * version field.
		 */
		version_field_address = (uint8_t *)&(test_wallet.unencrypted.version) - (uint8_t *)&test_wallet;
		version_field_counter = 0;

		while ((version_field_address + 4) <= ACCOUNTS_PARTITION_SIZE)
		{
			if ((version_field_address >= start_address) && ((version_field_address + 4) <= end_address))
			{
				/* version_field_address should be in the list somewhere. */
				found = false;

				for (j = 0; j < version_field_index; j++)
				{
					if (version_field_address == version_field_writes[j])
					{
						found = true;
						break;
					}
				}

				if (!found)
				{
					printf("sanitiseNonVolatileStorage() did not clear version field at 0x%08x\n", version_field_address);
					reportFailureWallet();
					abort = true;
					break;
				}

				version_field_counter++;
			}

			version_field_address += sizeof(WalletRecord);
		}	/* End while ((version_field_address + 4) <= ACCOUNTS_PARTITION_SIZE) */

		if (abort)
			break;

		/*
		 * sanitiseNonVolatileStorage() should clear the version fields of any
		 * wallets in range, but it should also ignore all version fields not
		 * in range.
		 */
		if (version_field_counter != version_field_index)
		{
			printf("sanitiseNonVolatileStorage() is clearing out of range version fields\n");
			reportFailureWallet();
			abort = true;
			break;
		}
	}	/* End for (i = 0; i < 5000; i++) */

	if (!abort)
		reportSuccessWallet();

	suppress_write_debug_info = false;	/* can start reporting writes again */

	/* Check that sanitising the global partition does not touch any version fields. */
	printf("Check that sanitising the global partition does not touch any version fields\n");

	clearVersionFieldWriteLog();
	sanitisePartition(PARTITION_GLOBAL);

	if (version_field_index == 0)
		reportSuccessWallet();
	else
	{
		printf("sanitisePartition(PARTITION_GLOBAL) is touching version fields\n");
		reportFailureWallet();
	}

	/* Check that sanitising the accounts partition touches all version fields. */
	printf("Check that sanitising the accounts partition touches all version fields\n");

	clearVersionFieldWriteLog();
	sanitisePartition(PARTITION_ACCOUNTS);

	/*
	 * version_field_address is stepped through every possible address
	 * (ignoring start_address and end_address) that could hold a wallet's
	 * version field.
	 */
	version_field_address = (uint8_t *)&(test_wallet.unencrypted.version) - (uint8_t *)&test_wallet;
	version_field_counter = 0;

	while ((version_field_address + 4) <= ACCOUNTS_PARTITION_SIZE)
	{
		version_field_counter++;
		version_field_address += sizeof(WalletRecord);
	}

	if (version_field_index == version_field_counter)
		reportSuccessWallet();
	else
	{
		printf("sanitisePartition(PARTITION_ACCOUNTS) not touching all version fields\n");
		reportFailureWallet();
	}

	/* Check that getNumberOfWallets() works and returns the appropriate value for various non-volatile storage sizes. */
	printf("Check that getNumberOfWallets() works and returns the appropriate value for various non-volatile storage sizes\n");

	abort = false;
	abort_error = false;

	/* Step in increments of 1 byte to look for off-by-one errors. */
	for (i = ACCOUNTS_PARTITION_SIZE; i < ACCOUNTS_PARTITION_SIZE + 1024; i++)
	{
		accounts_partition_size = i;
		num_wallets = 0;	/* Reset cache */
		returned_num_wallets = getNumberOfWallets();

		if (returned_num_wallets == 0)
		{
			printf("getNumberOfWallets() doesn't work\n");
			reportFailureWallet();
			abort_error = true;
			break;
		}

		stupidly_calculated_num_wallets = 0;

		for (j = 0; (int)(j + (sizeof(WalletRecord) - 1)) < i; j += sizeof(WalletRecord))
			stupidly_calculated_num_wallets++;

		if (stupidly_calculated_num_wallets != returned_num_wallets)
		{
			printf("getNumberOfWallets() returning inappropriate value\n");
			reportFailureWallet();
			abort = true;
			break;
		}
	}

	if (!abort)
		reportSuccessWallet();

	if (!abort_error)
		reportSuccessWallet();

	accounts_partition_size = ACCOUNTS_PARTITION_SIZE;
	num_wallets = 0;	/* Reset cache for next test */

	/* For all functions which accept wallet numbers, try some wallet numbers which are in or out of range. */
	printf("For all functions which accept wallet numbers, try some wallet numbers which are in or out of range\n");

	returned_num_wallets = getNumberOfWallets();
	checkWalletSpecFunctions(0, true);	/* First one */

	/* The next line does assume that returned_num_wallets > 1. */
	checkWalletSpecFunctions(returned_num_wallets - 1, true);	/* Last one */
	checkWalletSpecFunctions(returned_num_wallets, false);		/* Out of range */

	/* The next line does assume that returned_num_wallets != 0xffffffff. */
	checkWalletSpecFunctions(returned_num_wallets + 1, false);	/* Out of range */
	checkWalletSpecFunctions(0xffffffff, false);				/* Out of range */

	/*
	 * Create one wallet and some addresses, then create another wallet with a
	 * different wallet number and see if it overwrites the first one
	 *(it shouldn't).
	 */
	printf("Create one wallet and some addresses, then create another wallet with a different wallet number and see if it overwrites the first one\n");

	uninitWallet();

	memcpy(name, "A wallet with wallet number 0           ", NAME_LENGTH);

	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);

	makeNewAddress(address1, &public_key);
	makeNewAddress(address1, &public_key);
	makeNewAddress(address1, &public_key);

	uninitWallet();

	memcpy(name2, "A wallet with wallet number 1           ", NAME_LENGTH);

	deleteWallet(1);

	newWallet(1, name2, false, NULL, false, NULL, 0);

	makeNewAddress(address2, &public_key);
	makeNewAddress(address2, &public_key);

	uninitWallet();
	initWallet(0, NULL, 0);

	ah = getNumAddresses();

	getAddressAndPublicKey(compare_address, &public_key, ah);

	if (memcmp(address1, compare_address, 20))
	{
		printf("Creating wallet 1 seems to mangle wallet 0\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/*
	 * Now:
	 * name contains name of wallet 0,
	 * name2 contains name of wallet 1,
	 * address1 contains the most recently created address in wallet 0,
	 * address2 contains the most recently created address in wallet 1.
	 */

	/* Unload wallet 0 then load wallet 1 and make sure wallet 1 was loaded. */
	printf("Unload wallet 0 then load wallet 1 and make sure wallet 1 was loaded\n");

	uninitWallet();
	initWallet(1, NULL, 0);

	ah = getNumAddresses();

	getAddressAndPublicKey(compare_address, &public_key, ah);

	if (memcmp(address2, compare_address, 20))
	{
		printf("Loading wallet 0 seems to prevent wallet 1 from being loaded\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check getWalletInfo() returns the name that was set for both wallets. */
	printf("Check getWalletInfo() returns the name that was set for both wallets\n");

	getWalletInfo(&version, compare_name, wallet_uuid, 0);

	if (memcmp(name, compare_name, NAME_LENGTH))
	{
		printf("Wallet 0's name got mangled\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	getWalletInfo(&version, compare_name, wallet_uuid, 1);

	if (memcmp(name2, compare_name, NAME_LENGTH))
	{
		printf("Wallet 1's name got mangled\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Set wallet 1 to have a different encryption key from wallet 0 and check that the correct encryption key (and only that one) works. */
	printf("Set wallet 1 to have a different encryption key from wallet 0 and check that the correct encryption key (and only that one) works\n");

	deleteWallet(0);
	newWallet(0, name, false, NULL, false, test_password0, sizeof(test_password0));

	makeNewAddress(address1, &public_key);

	uninitWallet();
	deleteWallet(1);

	newWallet(1, name2, false, NULL, false, test_password1, sizeof(test_password1));

	makeNewAddress(address2, &public_key);

	uninitWallet();

	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 0 with correct key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	if (initWallet(0, test_password1, sizeof(test_password1)) == WALLET_NO_ERROR)
	{
		printf("Wallet 0 can be loaded with wallet 1's key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	if (initWallet(1, test_password0, sizeof(test_password0)) == WALLET_NO_ERROR)
	{
		printf("Wallet 1 can be loaded with wallet 0's key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	if (initWallet(1, test_password1, sizeof(test_password1)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 1 with correct key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	/* Change wallet 1's key and check that it doesn't change wallet 0. */
	printf("Change wallet 1's key and check that it doesn't change wallet 0\n");

	initWallet(1, test_password1, sizeof(test_password1));

	changeEncryptionKey(new_test_password, sizeof(new_test_password));

	uninitWallet();

	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 0 with correct key after wallet 1's key was changed\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	/* Check that wallet 1 can be loaded with the new key. */
	printf("Check that wallet 1 can be loaded with the new key\n");

	if (initWallet(1, new_test_password, sizeof(new_test_password)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 1 with correct key after wallet 1's key was changed\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	/*
	 * So far, the multiple wallet tests have only looked at wallets 0 and 1.
	 * The following test creates the maximum number of wallets that
	 * non-volatile storage can hold and checks that they can all create
	 * addresses independently.
	 */
	printf("create the maximum number of wallets that non-volatile storage can hold and checks that they can all create addresses independently\n");

	returned_num_wallets = getNumberOfWallets();
	address_buffer = (uint8_t *)malloc(returned_num_wallets * 20);

	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		deleteWallet((uint32_t)i);
		newWallet((uint32_t)i, name, false, NULL, false, NULL, 0);
		makeNewAddress(&(address_buffer[i * 20]), &public_key);
		uninitWallet();
	}

	abort = false;

	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		initWallet((uint32_t)i, NULL, 0);
		getAddressAndPublicKey(compare_address, &public_key, 1);

		if (memcmp(&(address_buffer[i * 20]), compare_address, 20))
		{
			printf("Wallet %d got corrupted\n", i);
			reportFailureWallet();
			abort = true;
			break;
		}

		uninitWallet();
	}

	if (!abort)
		reportSuccessWallet();

	/* Check that addresses from each wallet are unique. */
	printf("Check that addresses from each wallet are unique\n");

	abort_duplicate = false;

	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Different wallets generate the same addresses\n");
				abort_duplicate = true;
				reportFailureWallet();
				break;
			}
		}

		if (abort_duplicate)
			break;
	}

	if (!abort_duplicate)
		reportSuccessWallet();

	free(address_buffer);

	/* Clear NV storage, then create a new hidden wallet. */
	printf("Clear NV storage, then create a new hidden wallet\n");

	sanitiseEverything();

	nonVolatileRead((uint8_t *)&unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(unencrypted_part));

	memcpy(name, "This will be ignored                    ", NAME_LENGTH);

	if (newWallet(0, name, false, NULL, true, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Couldn't create new hidden wallet\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that the hidden wallet can function as a wallet by creating an address. */
	printf("Check that the hidden wallet can function as a wallet by creating an address\n");

	if (makeNewAddress(address1, &public_key) == BAD_ADDRESS_HANDLE)
	{
		printf("Couldn't create new address in hidden wallet\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	/* Check that unencrypted part (which contains name/version) wasn't touched. */
	printf("Check that unencrypted part (which contains name/version) wasn't touched\n");

	nonVolatileRead((uint8_t *)&compare_unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(compare_unencrypted_part));

	if (memcmp(&unencrypted_part, &compare_unencrypted_part, sizeof(unencrypted_part)))
	{
		printf("Creation of hidden wallet writes to unencrypted portion of wallet storage\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Is it possible to load the hidden wallet? */
	printf("Is it possible to load the hidden wallet?\n");

	uninitWallet();

	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* It should be possible to change the encryption key of a hidden wallet. */
	printf("It should be possible to change the encryption key of a hidden wallet\n");

	if (changeEncryptionKey(new_test_password, sizeof(new_test_password)) != WALLET_NO_ERROR)
	{
		printf("Couldn't change encryption key for hidden wallet\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that the unencrypted part (which contains name/version) wasn't touched. */
	printf("Check that the unencrypted part (which contains name/version) wasn't touched\n");

	uninitWallet();

	nonVolatileRead((uint8_t *)&compare_unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(compare_unencrypted_part));

	if (memcmp(&unencrypted_part, &compare_unencrypted_part, sizeof(unencrypted_part)))
	{
		printf("Key change on hidden wallet results in writes to unencrypted portion of wallet storage\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* The hidden wallet should be loadable with the new key but not the old. */
	printf("The hidden wallet should be loadable with the new key but not the old\n");

	uninitWallet();

	if (initWallet(0, new_test_password, sizeof(new_test_password)) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet after encryption key change\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NOT_THERE)
	{
		printf("Could load hidden wallet with old encryption key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Change key to all 00s (representing an "unencrypted" wallet) and do the above key change tests. */
	printf("Change key to all 00s and do the above key change tests\n");

	initWallet(0, new_test_password, sizeof(new_test_password));

	if (changeEncryptionKey(NULL, 0) != WALLET_NO_ERROR)
	{
		printf("Couldn't change encryption key for hidden wallet 2\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	nonVolatileRead((uint8_t *)&compare_unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(compare_unencrypted_part));

	if (memcmp(&unencrypted_part, &compare_unencrypted_part, sizeof(unencrypted_part)))
	{
		printf("Key change on hidden wallet results in writes to unencrypted portion of wallet storage 2\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	if (initWallet(0, NULL, 0) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet after encryption key change 2\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	uninitWallet();

	if (initWallet(0, new_test_password, sizeof(new_test_password)) != WALLET_NOT_THERE)
	{
		printf("Could load hidden wallet with old encryption key 2\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Wallet name changes on a hidden wallet should be disallowed. */
	printf("Wallet name changes on a hidden wallet should be disallowed\n");

	initWallet(0, NULL, 0);

	memcpy(name2, "This will also be ignored               ", NAME_LENGTH);

	if (changeWalletName(name2) != WALLET_INVALID_OPERATION)
	{
		printf("Wallet name change is allowed on a hidden wallet\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that the wallet is still intact by getting the previously generated address from it. */
	printf("Check that the wallet is still intact by getting the previously generated address from it\n");

	initWallet(0, NULL, 0);

	if (getAddressAndPublicKey(address2, &public_key, 1) != WALLET_NO_ERROR)
	{
		printf("Couldn't get address from hidden wallet\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	if (memcmp(address1, address2, 20))
	{
		printf("Addresses in hidden wallet are getting mangled\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Create a non-hidden wallet, then overwrite it with a hidden wallet. The resulting version field should still be VERSION_NOTHING_THERE. */
	printf("Create a non-hidden wallet, then overwrite it with a hidden wallet\n");

	uninitWallet();
	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);
	deleteWallet(0);

	newWallet(0, name, false, NULL, true, NULL, 0);
	getWalletInfo(&version, temp, wallet_uuid, 0);

	if (version != VERSION_NOTHING_THERE)
	{
		printf("Hidden wallet's version field is not VERSION_NOTHING_THERE\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Create two wallets. Their UUIDs should not be the same. */
	printf("Create two wallets. Their UUIDs should not be the same\n");

	uninitWallet();
	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);
	deleteWallet(1);

	newWallet(1, name, false, NULL, false, NULL, 0);
	getWalletInfo(&version, temp, wallet_uuid, 0);
	getWalletInfo(&version, temp, wallet_uuid2, 1);

	if (!memcmp(wallet_uuid, wallet_uuid2, UUID_LENGTH))
	{
		printf("Wallet UUIDs not unique\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Overwrite wallet 0. The UUID should change. */
	printf("Overwrite wallet 0. The UUID should change.\n");

	uninitWallet();
	deleteWallet(0);

	newWallet(0, name, false, NULL, false, test_password0, sizeof(test_password0));
	getWalletInfo(&version, temp, wallet_uuid2, 0);

	if (!memcmp(wallet_uuid, wallet_uuid2, UUID_LENGTH))
	{
		printf("Wallet UUIDs aren't changing on overwrite\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Perform a few operations on the wallet. The wallet UUID shouldn't change. */
	printf("Perform a few operations on the wallet. The wallet UUID shouldn't change\n");

	uninitWallet();
	getWalletInfo(&version, temp, wallet_uuid, 0);

	initWallet(0, test_password0, sizeof(test_password0));

	changeEncryptionKey(NULL, 0);

	makeNewAddress(address1, &public_key);

	changeWalletName(name2);

	uninitWallet();

	initWallet(0, NULL, 0);

	getWalletInfo(&version, temp, wallet_uuid2, 0);

	if (memcmp(wallet_uuid, wallet_uuid2, UUID_LENGTH))
	{
		printf("Wallet UUIDs changing when the wallet is used\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that getMasterPublicKey() works. */
	printf("Check that getMasterPublicKey() works\n");

	uninitWallet();
	deleteWallet(0);

	newWallet(0, name, false, NULL, false, NULL, 0);
	initWallet(0, NULL, 0);

	if (getMasterPublicKey(&master_public_key, chain_code) != WALLET_NO_ERROR)
	{
		printf("getMasterPublicKey() fails in the simplest case\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that wallet public keys can be derived from the public key and chain code that getMasterPublicKey() returned. */
	printf("Check that wallet public keys can be derived from the public key and chain code that getMasterPublicKey() returned\n");

	generateDeterministicPublicKey(&public_key, &master_public_key, chain_code, 1);

	makeNewAddress(address1, &compare_public_key);

	if (memcmp(&public_key, &compare_public_key, sizeof(PointAffine)))
	{
		printf("Address 1 can't be derived from master public key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	generateDeterministicPublicKey(&public_key, &master_public_key, chain_code, 2);

	makeNewAddress(address1, &compare_public_key);

	if (memcmp(&public_key, &compare_public_key, sizeof(PointAffine)))
	{
		printf("Address 2 can't be derived from master public key\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	/* Check that sanitisePartition() only affects one partition. */
	printf("Check that sanitisePartition() only affects one partition\n");

	suppress_set_entropy_pool = true;	/* Avoid spurious writes to global partition */

	memset(copy_of_nv, 0, sizeof(copy_of_nv));
	memset(copy_of_nv2, 1, sizeof(copy_of_nv2));

	nonVolatileRead(copy_of_nv, PARTITION_GLOBAL, 0, GLOBAL_PARTITION_SIZE);

	sanitisePartition(PARTITION_ACCOUNTS);

	nonVolatileRead(copy_of_nv2, PARTITION_GLOBAL, 0, GLOBAL_PARTITION_SIZE);

	if (memcmp(copy_of_nv, copy_of_nv2, GLOBAL_PARTITION_SIZE))
	{
		printf("sanitisePartition(PARTITION_ACCOUNTS) is touching global partition\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	memset(copy_of_nv, 0, sizeof(copy_of_nv));
	memset(copy_of_nv2, 1, sizeof(copy_of_nv2));

	nonVolatileRead(copy_of_nv, PARTITION_ACCOUNTS, 0, ACCOUNTS_PARTITION_SIZE);

	sanitisePartition(PARTITION_GLOBAL);

	nonVolatileRead(copy_of_nv2, PARTITION_ACCOUNTS, 0, ACCOUNTS_PARTITION_SIZE);

	if (memcmp(copy_of_nv, copy_of_nv2, ACCOUNTS_PARTITION_SIZE))
	{
		printf("sanitisePartition(PARTITION_GLOBAL) is touching accounts partition\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	suppress_set_entropy_pool = false;

	/* Check that entropy pool can still be loaded after sanitiseEverything(). */
	printf("Check that entropy pool can still be loaded after sanitiseEverything()\n");

	initialiseDefaultEntropyPool();

	sanitiseEverything();

	if (getEntropyPool(pool_state))
	{
		printf("Entropy pool can't be loaded after sanitiseEverything()\n");
		reportFailureWallet();
	}
	else
		reportSuccessWallet();

	//fclose(wallet_storage_file);

	finaliseTestsWallet();

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}
