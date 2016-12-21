/** \file
  *
  * \brief Manages the storage and generation of Bitcoin addresses.
  *
  * Addresses are stored in wallets, which can be
  * "loaded" or "unloaded". A loaded wallet can have operations (eg. new
  * address) performed on it, whereas an unloaded wallet can only sit dormant.
  * Addresses aren't actually physically stored in non-volatile storage;
  * rather a seed for a deterministic private key generation algorithm is
  * stored and private keys are generated when they are needed. This means
  * that obtaining an address is a slow operation (requiring a point
  * multiply), so the host should try to remember all public keys and
  * addresses. The advantage of not storing addresses is that very little
  * non-volatile storage space is needed per wallet.
  *
  * Wallets can be encrypted or unencrypted. Actually, technically, all
  * wallets are encrypted. However, wallets marked as "unencrypted" are
  * encrypted using an encryption key consisting of all zeros. This purely
  * semantic definition was done to avoid having to insert special cases
  * every-time encrypted storage needed to be accessed.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "extern.h"
#include "hwinterface.h"
#include "prandom.h"
#include "storage_common.h"
#include "tz_functions.h"
#include "wallet.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/** Get the current number of addresses in a wallet.
  * \return The current number of addresses on success, or 0 if an error
  *         occurred. Use walletGetLastError() to get more detail about
  *         an error.
  */
uint32_t getNumAddresses(void)
{
    return getNumAddressesTZ();
}

/** Given an address handle, use the deterministic private key
  * generator to generate the private key associated with that address handle.
  * \param out The private key will be written here (if everything goes well).
  *            This must be a byte array with space for 32 bytes.
  * \param ah The address handle to obtain the private key of.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getPrivateKey(uint8_t *out, AddressHandle ah)
{
    return getPrivateKeyTestTZ(out, ah);
}

/** Given an address handle, use the deterministic private key
  * generator to generate the address and public key associated
  * with that address handle.
  * \param out_address The address will be written here (if everything
  *                    goes well). This must be a byte array with space for
  *                    20 bytes.
  * \param out_public_key The public key corresponding to the address will
  *                       be written here (if everything goes well).
  * \param ah The address handle to obtain the address/public key of.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getAddressAndPublicKey(uint8_t *out_address, PointAffine *out_public_key, AddressHandle ah)
{
    return getAddressAndPublicKeyTZ(out_address, out_public_key, ah);
}

/** Get the master public key of the currently loaded wallet. Every public key
  * (and address) in a wallet can be derived from the master public key and
  * chain code. However, even with possession of the master public key, all
  * private keys are still secret.
  * \param out_public_key The master public key will be written here.
  * \param out_chain_code The chain code will be written here. This must be a
  *                       byte array with space for 32 bytes.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getMasterPublicKey(PointAffine *out_public_key, uint8_t *out_chain_code)
{
    return getMasterPublicKeyTZ(out_public_key, out_chain_code);
}

/** Change the encryption key of a wallet.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeEncryptionKey(const uint8_t *password, const unsigned int password_length)
{
    return changeEncryptionKeyTZ(password, password_length);
}

/** Find out what the most recent error which occurred in any wallet function
  * was. If no error occurred in the most recent wallet function that was
  * called, this will return #WALLET_NO_ERROR.
  * \return See #WalletErrorsEnum for possible values.
  */
WalletErrors walletGetLastError(void)
{
    return last_error;
}

/** Initialise a wallet (load it if it's there).
  * \param wallet_spec The wallet number of the wallet to load.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors initWallet(uint32_t wallet_spec, const uint8_t *password, const unsigned int password_length)
{
    if (uninitWalletTZ() != WALLET_NO_ERROR)
        return last_error;  /* Propagate the error code */

    if (getNumberOfWallets() == 0)
        return last_error; /* Propagate the error code */

    if (wallet_spec >= num_wallets)
    {
        last_error = WALLET_INVALID_WALLET_NUM;
        return last_error;
    }

    return initWalletTZ(wallet_spec, password, password_length);
}

/** Unload wallet, so that it cannot be used until initWallet() is called.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors uninitWallet(void)
{
    return uninitWalletTZ();
}

/** Get the number of wallets which can fit in non-volatile storage, assuming
  * the storage format specified in storage_common.h.
  * This will set #num_wallets.
  * \return The number of wallets on success, or 0 if a read error occurred.
  */
uint32_t getNumberOfWallets(void)
{
    uint32_t size;

    last_error = WALLET_NO_ERROR;

    if (num_wallets == 0)
    {
        /*
         * Need to calculate number of wallets that can fit in non-volatile
         * storage.
         */
        if (nonVolatileGetSize(&size, PARTITION_ACCOUNTS) == NV_NO_ERROR)
          num_wallets = size / sizeof(WalletRecord);
        else
        {
          last_error = WALLET_READ_ERROR;
          num_wallets = 0;
        }
    }

    return num_wallets;
}

/** Obtain publicly available information about a wallet. "Publicly available"
  * means that the leakage of that information would have a relatively low
  * impact on security (compared to the leaking of, say, the deterministic
  * private key generator seed).
  *
  * Note that unlike most of the other wallet functions, this function does
  * not require the wallet to be loaded. This is so that a user can be
  * presented with a list of all the wallets stored on a hardware Bitcoin
  * wallet, without having to know the encryption key to each wallet.
  * \param out_version The version (see #WalletVersion) of the wallet will be
  *                    written to here (if everything goes well).
  * \param out_name The (space-padded) name of the wallet will be written
  *                 to here (if everything goes well). This should be a
  *                 byte array with enough space to store #NAME_LENGTH bytes.
  * \param out_uuid The wallet UUID will be written to here (if everything
  *                 goes well). This should be a byte array with enough space
  *                 to store #UUID_LENGTH bytes.
  * \param wallet_spec The wallet number of the wallet to query.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getWalletInfo(uint32_t *out_version, uint8_t *out_name, uint8_t *out_uuid, uint32_t wallet_spec)
{
    if (getNumberOfWallets() == 0)
        return last_error;  /* Propagate the error code */

    if (wallet_spec >= num_wallets)
    {
        last_error = WALLET_INVALID_WALLET_NUM;
        return last_error;
    }

    return getWalletInfoTZ(out_version, out_name, out_uuid, wallet_spec);
}

/** Change the name of the currently loaded wallet.
  * \param new_name This should point to #NAME_LENGTH bytes (padded with
  *                 spaces if necessary) containing the new desired name of
  *                 the wallet.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeWalletName(uint8_t *new_name)
{
    return changeWalletNameTZ(new_name);
}

/** Create new wallet. A brand new wallet contains no addresses and should
  * have a unique, unpredictable deterministic private key generation seed.
  * \param wallet_spec The wallet number of the new wallet.
  * \param name Should point to #NAME_LENGTH bytes (padded with spaces if
  *             necessary) containing the desired name of the wallet.
  * \param use_seed If this is true, then the contents of seed will be
  *                 used as the deterministic private key generation seed.
  *                 If this is false, then the contents of seed will be
  *                 ignored.
  * \param seed The deterministic private key generation seed to use in the
  *             new wallet. This should be a byte array of length #SEED_LENGTH
  *             bytes. This parameter will be ignored if use_seed is false.
  * \param make_hidden Whether to make the new wallet a hidden wallet.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred. If this returns #WALLET_NO_ERROR, then the
  *         wallet will also be loaded.
  * \warning This will erase the current one.
  */
WalletErrors newWallet(uint32_t wallet_spec, uint8_t *name, bool use_seed, uint8_t *seed, bool make_hidden, const uint8_t *password, const unsigned int password_length)
{
    if (uninitWalletTZ() != WALLET_NO_ERROR)
        return last_error;  /* Propagate the error code. */

    /*
     * getNumberOfWallets() sets the value for num_wallets so it's essential
     * that the order of execution is respected if any change is made.
     */
    if (getNumberOfWallets() == 0)
        return last_error;  /* Propagate the error code. */

    if (wallet_spec >= num_wallets)
    {
        last_error = WALLET_INVALID_WALLET_NUM;
        return last_error;
    }

    return newWalletTZ(wallet_spec, name, use_seed, seed, make_hidden, password, password_length);
}

/** Initiate a wallet backup of the currently loaded wallet.
  * \param do_encrypt Whether the wallet backup will be written in encrypted
  *                   form.
  * \param destination_device See writeBackupSeed().
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors backupWallet(bool do_encrypt, uint32_t destination_device)
{
    uint8_t seed[SEED_LENGTH];
    bool response;

    if (do_encrypt)
        assert(SEED_LENGTH % 16 == 0);

    if (getSeedTZ(seed, do_encrypt) == false)
        return last_error;

    response = writeBackupSeed(seed, do_encrypt, destination_device);

    if (response)
    {
        last_error = WALLET_BACKUP_ERROR;
        return last_error;
    }
    else
    {
        last_error = WALLET_NO_ERROR;
        return last_error;
    }
}

/** Generate a new address using the deterministic private key generator.
  * \param out_address The new address will be written here (if everything
  *                    goes well). This must be a byte array with space for
  *                    20 bytes.
  * \param out_public_key The public key corresponding to the new address will
  *                       be written here (if everything goes well).
  * \return The address handle of the new address on success,
  *         or #BAD_ADDRESS_HANDLE if an error occurred.
  *         Use walletGetLastError() to get more detail about an error.
  */
AddressHandle makeNewAddress(uint8_t *out_address, PointAffine *out_public_key)
{
    return makeNewAddressTZ(out_address, out_public_key);
}

/** Sanitize (clear) a selected area of non-volatile storage.
  * \param partition The partition the area is contained in. Must be one
  *                  of #NVPartitions.
  * \param start The first address within the partition which will be cleared.
  *              Must be a multiple of 4.
  * \param length The number of bytes to clear. Must be a multiple of 4.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors sanitiseNonVolatileStorage(NVPartitions partition, uint32_t start, uint32_t length)
{
    uint8_t pool_state[ENTROPY_POOL_LENGTH];
    uint8_t pass;
    uint32_t address;
    uint32_t bytes_written;
    uint8_t buffer[32];
    uint32_t bytes_to_write;
    NonVolatileReturn response;

    if (getEntropyPool(pool_state))
    {
        last_error = WALLET_RNG_FAILURE;
        return last_error;
    }

    /*
     * The following check guards all occurrences of (address + length + offset)
     * from integer overflow, for all reasonable values of "offset".
     */
    if ((start > 0x10000000) || (length > 0x10000000))
    {
        /* Address migth overflow */
        last_error = WALLET_BAD_ADDRESS;
        return last_error;
    }

    /*
     * The "must be a multiple of 4" checks are there so that version  fields
     * (which are 4 bytes long) are always either completely cleared or not
     * touched at all.
     */
    if (((start % 4) != 0) || ((length % 4) != 0))
    {
        /* Start and length not multiples of 4. */
        last_error = WALLET_BAD_ADDRESS;
        return last_error;
    }

    /*
     * 4 pass format: all 0s, all 1s, random, random. This ensures that every
     * bit is cleared at least once, set at least once and ends up in an
     * unpredictable state. It is crucial that the last pass is random for two
     * reasons:
     * 1) A new device UUID is written, if necessary.
     * 2) Hidden wallets are actually plausibly deniable.
     */
    for (pass = 0; pass < 4; pass++)
    {
        address = start;

        bytes_written = 0;

        while (bytes_written < length)
        {
            if (pass == 0)
                memset(buffer, 0, sizeof(buffer));
            else if (pass == 1)
                memset(buffer, 0xff, sizeof(buffer));
            else
            {
                if (getRandom256TemporaryPool(buffer, pool_state))
                {
                    /*
                     * Before returning, attempt to write the persistent entropy
                     * pool state back into non-volatile memory. The return value
                     * of setEntropyPool() is ignored because if a failure occurs,
                     * then WALLET_RNG_FAILURE is a suitable return value anyway.
                     */
                    if (is_test_wallet)
                    {
                        if (!suppress_set_entropy_pool)
                            setEntropyPool(pool_state);
                    }
                    else
                        setEntropyPool(pool_state);

                    last_error = WALLET_RNG_FAILURE;

                    return last_error;
                }
            }

            bytes_to_write = length - bytes_written;

            if (bytes_to_write > sizeof(buffer))
                bytes_to_write = sizeof(buffer);

            if (bytes_to_write > 0)
            {
                response = nonVolatileWrite(buffer, partition, address, bytes_to_write);

                if (response != NV_NO_ERROR)
                {
                    last_error = WALLET_WRITE_ERROR;
                    return last_error;
                }
            }

            address += bytes_to_write;

            bytes_written += bytes_to_write;
        } /* end while (bytes_written < length) */

        /*
         * After each pass, flush write buffers to ensure that non-volatile memory
         * is actually overwritten.
         */
        response = nonVolatileFlush();

        if (response != NV_NO_ERROR)
        {
            last_error = WALLET_WRITE_ERROR;
            return last_error;
        }
    } /* End for (pass = 0; pass < 4; pass++) */

    if (is_test_wallet)
    {
        if (!suppress_set_entropy_pool)
        {
            /* Write back persistent entropy pool state. */
            if (setEntropyPool(pool_state))
            {
                last_error = WALLET_RNG_FAILURE;
                return last_error;
            }
        }
    }
    else
    {
        /* Write back persistent entropy pool state. */
        if (setEntropyPool(pool_state))
        {
            last_error = WALLET_RNG_FAILURE;
            return last_error;
        }
    }

    /*
     * At this point the selected area is now filled with random data. Some functions
     * in this file expect non-random data in certain locations. If the selected area
     * includes the device UUID, then a new device UUID needs to be written. But if
     * the selected area includes the device UUID, then it will be overwritten with
     * random data in the above loop. Thus no additional work is needed. Write
     * VERSION_NOTHING_THERE to all possible locations of the version field. This
     * ensures that a wallet won't accidentally (1 in 2 ^ 31 chance) be recognised as
     * a valid wallet by getWalletInfo().
     */
    if (partition == PARTITION_ACCOUNTS)
    {
        address = start;
        address /= sizeof(WalletRecord);
        address *= sizeof(WalletRecord);
        address += offsetof(WalletRecord, unencrypted.version);

        /*
         * Address is now rounded down to the first possible address where the version
         * field of a wallet could be stored.
         */
        memset(buffer, 0, sizeof(uint32_t));

        while ((address + sizeof(uint32_t)) <= (start + length))
        {
            /*
             * An additional range check against start is needed because the initial
             * value of address is rounded down; thus it could be rounded down below start.
             */
            if (address >= start)
            {
                response = nonVolatileWrite(buffer, partition, address, sizeof(uint32_t));

                if (response == NV_NO_ERROR)
                    response = nonVolatileFlush();
                else if (response != NV_NO_ERROR)
                {
                    last_error = WALLET_WRITE_ERROR;
                    return last_error;
                }

                if (response == NV_NO_ERROR && is_test_wallet)
                    logVersionFieldWrite(address);
            }

            address += sizeof(WalletRecord);
        } /* end while ((address + sizeof(uint32_t)) <= (start + length)) */
    } /* end if (partition == PARTITION_ACCOUNTS) */

    last_error = WALLET_NO_ERROR;

    return last_error;
}

/** Sanitize (clear) the entire contents of a partition.
  * \param partition The partition to clear. Must be one of #NVPartitions.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors sanitisePartition(NVPartitions partition)
{
  uint32_t size;

  if (nonVolatileGetSize(&size, partition) != NV_NO_ERROR)
  {
    last_error = WALLET_BAD_ADDRESS;
    return last_error;
  }

  last_error = sanitiseNonVolatileStorage(partition, 0, size);

  return last_error;
}

/** Sanitize (clear) all partitions.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors sanitiseEverything(void)
{
  last_error = sanitisePartition(PARTITION_GLOBAL);

  if (last_error == WALLET_NO_ERROR)
    last_error = sanitisePartition(PARTITION_ACCOUNTS);

  return last_error;
}

/** Delete a wallet, so that it's contents can no longer be retrieved from
  * non-volatile storage.
  * \param wallet_spec The wallet number of the wallet to delete. The wallet
  *                    doesn't have to "exist"; calling this function for a
  *                    non-existent wallet will clear the non-volatile space
  *                    associated with it. This is useful for deleting a
  *                    hidden wallet.
  * \warning This is irreversible; the only way to access the wallet after
  *          deletion is to restore a backup.
  */
WalletErrors deleteWallet(uint32_t wallet_spec)
{
    uint32_t address;

    if (getNumberOfWallets() == 0)
        return last_error;  /* Propagate error code */

    if (wallet_spec >= num_wallets)
    {
        last_error = WALLET_INVALID_WALLET_NUM;
        return last_error;
    }

    /*
     * Always unload current wallet, just in case the current wallet is the
     * one being deleted.
     */
    if (uninitWallet() != WALLET_NO_ERROR)
        return last_error;  /* Propagate error code */

    address = wallet_spec * sizeof(WalletRecord);

    last_error = sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, address, sizeof(WalletRecord));

    return last_error;
}
