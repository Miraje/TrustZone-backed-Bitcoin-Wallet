/** \file
  *
  * \brief Defines the overall layout of non-volatile storage.
  *
  * The overall layout of non-volatile storage consists of the global (stuff
  * that applies to all wallets) data followed by each wallet record.
  * This file does not describe the format of an individual
  * wallet record; rather it describes where those records go in non-volatile
  * storage.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "extern.h"
#include "hwinterface.h"
#include "storage_common.h"
#include "test_performance.h"
#include "tz_functions.h"

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>

/** Calls the respective function in TruztZone Client Application (defined in
  * tz_function.c). See #createWalletStorageTZ() for more details.
  */
void createWalletStorage(void)
{
    createWalletStorageTZ();
}

/** Calls the respective function in TruztZone Client Application (defined in
  * tz_function.c). See #openWalletStorageTZ() for more details.
  */
void openWalletStorage(void)
{
    openWalletStorageTZ();
}

/** Calls the respective function in TruztZone Client Application (defined in
  * tz_function.c). See #closeWalletStorageTZ() for more details.
  */
void closeWalletStorage(void)
{
    closeWalletStorageTZ();
}

/** Calls the respective function in TruztZone Client Application (defined in
  * tz_function.c). See #deleteWalletStorageTZ() for more details.
  */
void deleteWalletStorage(void)
{
    deleteWalletStorageTZ();
}

/** Calls the respective function in TruztZone Client Application (defined in
  * tz_function.c). See #seekWalletStorageTZ() for more details.
  * \warning The position is relatively to entire wallet storage and not to an
  *          individually partition.
  */
void seekWalletStorage(int32_t position)
{
    /* Checking if the position given is valid */
    if (position > NV_MEMORY_SIZE || position < 0)
        errx(1, "NV_INVALID_ADDRESS when seeking wallet storage.\n");

    seekWalletStorageTZ(position);
}

/** Get size of a partition.
  * \param out_size On success, the size of the partition (in number of bytes)
  *                 will be written here.
  * \param partition Partition to query. Must be one of #NVPartitions.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileGetSize(uint32_t *out_size, NVPartitions partition)
{
    if (partition == PARTITION_GLOBAL)
    {
        *out_size = GLOBAL_PARTITION_SIZE;
        return NV_NO_ERROR;
    }
    else if (partition == PARTITION_ACCOUNTS)
    {
        *out_size = accounts_partition_size;
        return NV_NO_ERROR;
    }
    else
        return NV_INVALID_ADDRESS;
}

/** Writes one byte to the wallet storage. The position of byte to be written
  * must be seek-ed before using #seekWalletStorage().
  * \param data On success, the byte that will be written into the storage.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning If the desired position to written is not seek-ed the data is
  *          written wherever the position in the data stream of the wallet
  *          storage is.
  */
NonVolatileReturn nonVolatileWrite1Byte(uint8_t *data)
{
    write1ByteWalletStorageTZ(data);

    return NV_NO_ERROR;
}

/** Reads one byte from the wallet storage. The position of byte to be read
  * must be seek-ed before using #seekWalletStorage().
  * \param data On success, the byte that will be read from the storage.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning If the desired position to be read is not seek-ed, the data is
  *          read from wherever the position in the data stream of the wallet
  *          storage is.
  */
NonVolatileReturn nonVolatileRead1Byte(uint8_t *data)
{
    read1ByteWalletStorageTZ(data);

    return NV_NO_ERROR;
}

/** Check that an address range lies entirely within a partition, and tweak
  * the address to convert from partition offset to non-volatile memory offset.
  * \param address Address (offset) within a partition.
  * \param partition The partition to check against. Must be one
  *                  of #NVPartitions.
  * \param length The number of bytes in the address range.
  * \return See #NonVolatileReturnEnum for return values.
  */
static NonVolatileReturn checkAndTweakAddress(uint32_t *address, NVPartitions partition, uint32_t length)
{
    uint32_t size;
    NonVolatileReturn response;

    /* Some sanity checks */
    if ((*address >= NV_MEMORY_SIZE) || (length > NV_MEMORY_SIZE) || ((*address + length) > NV_MEMORY_SIZE))
        return NV_INVALID_ADDRESS;

    /* Check that address range falls entirely within partition. */
    response = nonVolatileGetSize(&size, partition);

    if (response != NV_NO_ERROR)
        return response;

    if ((*address + length) > size)
        return NV_INVALID_ADDRESS;

    /*
     * Add partition base address to convert from partition offset to
     * non-volatile memory offset.
     */
    if (partition == PARTITION_ACCOUNTS)
        *address += GLOBAL_PARTITION_SIZE;

    return NV_NO_ERROR;
}

/** Writes to non-volatile storage. All platform-independent code assumes that
  * non-volatile memory acts like NOR flash/EEPROM.
  * \param data A pointer to the data to be written.
  * \param partition The partition to write to. Must be one of #NVPartitions.
  * \param address Byte offset specifying where in the partition to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
NonVolatileReturn nonVolatileWrite(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length)
{
    NonVolatileReturn nv_error;;
    uint32_t simple_address;
    uint32_t i;

    /*
     * Get the global address for the non-volatile storage (not the address
     * inside the partition)
     */
    nv_error = checkAndTweakAddress(&address, partition, length);

    if (nv_error != NV_NO_ERROR)
        return nv_error;

    simple_address = address;

    /* If the partition is 'accounts' then remove the offset */
    if (partition == PARTITION_ACCOUNTS)
        simple_address -= GLOBAL_PARTITION_SIZE;

    if (is_test_wallet)
    {
        if (length > 0)
        {
            if (simple_address < minimum_address_written[partition])
                minimum_address_written[partition] = simple_address;

            if ((simple_address + length - 1) > maximum_address_written[partition])
                maximum_address_written[partition] = simple_address + length - 1;
        }
    }

    /*
     * Don't output write debugging info when testing prandom.c,
     * otherwise the console will go crazy (since they do a lot of writing).
     */
    if(!is_test_prandom)
    {
        if (!suppress_write_debug_info)
        {
            printf("nv write, part = %d, addr = 0x%08x, length = 0x%04x, data =", (int)partition, (int)simple_address, (int)length);

            for (i = 0; i < length; i++)
                printf(" %02x", data[i]);

            printf("\n");
        }
    }

    nv_error = writeWalletStorageTZ(data, length, (int32_t)address);

    return nv_error;
}

/** Read from non-volatile storage.
  * \param data A pointer to the buffer which will receive the data.
  * \param partition The partition to read from. Must be one of #NVPartitions.
  * \param address Byte offset specifying where in the partition to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileRead(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length)
{
    NonVolatileReturn response;

    /*
     * Get the global address for the non-volatile storage (not the address
     * inside the partition)
     */
    response = checkAndTweakAddress(&address, partition, length);

    if (response != NV_NO_ERROR)
        return response;

    response = readWalletStorageTZ(data, length, (int32_t)address);

    return response;
}

/** Ensure that all buffered writes are committed to non-volatile storage.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileFlush(void)
{
    return flushWalletStorageTZ();
}

/** Overwrite anything in RAM which could contain sensitive data. "Sensitive
  * data" includes secret things like encryption keys and wallet private keys.
  * It also includes derived things like expanded keys and intermediate
  * results from elliptic curve calculations. Even past transaction data,
  * addresses and intermediate results from hash calculations could be
  * considered sensitive and should be overwritten.
  */
void sanitiseRam(void)
{
  /* For the moment it doesn't do anything */
  /* TODO USE OPTEE EXTENSIONS TO CLEAN THE CACHE AND SAY THAT IN THE COMMENTS. DONT FORGET TO USE THE DEFINE IF OPTEE */
}

/* TODO: say that write and read one byte are not safe for use they are just for testing */

/* TODO: add description  */
NonVolatileReturn nonVolatileCAFunctionCall(void)
{
    if (is_test_performance)
    {
        startTest("Measuring time of CA function call");
        CAFunctionCall();
        finishTest();
    }

    return NV_NO_ERROR;
}
