/** \file
  *
  * \brief It contains global variables definitions and related functions.
  *
  * The variables declared here are defined in extern.h and this is because
  * these variables are used as global variables. The most of them  are used
  * to be shared between a file and its respective test file and others are
  * used to indicate if a test (and which one) is being performed.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "extern.h"
#include "storage_common.h"
#include "wallet.h"

int version_field_index;
int num_outputs_seen;
bool is_test;
bool is_test_prandom;
bool is_test_wallet;
bool is_test_stream;
bool is_test_transaction;
bool is_test_performance;
bool broken_hwrng;
bool suppress_set_entropy_pool;
bool suppress_write_debug_info;
uint8_t test_chain_code[32];
uint8_t test_wallet_backup[SEED_LENGTH];
uint32_t maximum_address_written[2];
uint32_t minimum_address_written[2];
uint32_t accounts_partition_size;
uint32_t version_field_writes[ACCOUNTS_PARTITION_SIZE / sizeof(WalletRecord) + 2];
uint32_t num_wallets;
uint32_t transaction_data_index;
uint32_t transaction_length;
WalletErrors last_error;

/** Initialize some of the external variables. */
void initialiseExternVariables(void)
{
	is_test = false;
	is_test_prandom = false;
	is_test_stream = false;
	is_test_wallet = false;
	is_test_transaction = false;
    is_test_performance = false;
	broken_hwrng = false;
	suppress_set_entropy_pool = true;
	suppress_write_debug_info = true;
	accounts_partition_size = ACCOUNTS_PARTITION_SIZE;
    last_error = WALLET_NO_ERROR;
}
