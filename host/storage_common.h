/** \file storage_common.h
  *
  * \brief Defines some variables and functions implemented in storage_common.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef STORAGE_COMMON_H_INCLUDED
#define STORAGE_COMMON_H_INCLUDED

#include "hwinterface.h"

/** Address where the persistent entropy pool is located. */
#define ADDRESS_ENTROPY_POOL            64

/** Address where the checksum of the persistent entropy pool is located. */
#define ADDRESS_POOL_CHECKSUM           96

/** Address where device UUID is located. */
#define ADDRESS_DEVICE_UUID             128

/** Length of any UUID.
  * \warning This must also be a multiple of 16, since the block size of
  *          AES is 128 bits.
  */
#define UUID_LENGTH                     16

/** Size of global partition, in bytes. */
#define GLOBAL_PARTITION_SIZE           512

/** Size of accounts partition, in bytes. This is
  * just #NV_MEMORY_SIZE - #GLOBAL_PARTITION_SIZE.
  */
#define ACCOUNTS_PARTITION_SIZE         1024

/** Total number of bytes in non-volatile storage.
  * This has been temporarily reduced to the size of the wallet storage area.
  */
#define NV_MEMORY_SIZE                  1536

/** Number of bytes in a sector. */
#define SECTOR_SIZE                     4096

/** Bit mask applied to addresses to get the sector address. */
#define SECTOR_TAG_MASK                 (~(SECTOR_SIZE - 1))

/** Bit mask applied to addresses to get the offset within a sector. */
#define SECTOR_OFFSET_MASK              (SECTOR_SIZE - 1)

void initWalletStorage(void);
void createWalletStorage(void);
void openWalletStorage(void);
void closeWalletStorage(void);
void deleteWalletStorage(void);
void seekWalletStorage(int32_t position);
NonVolatileReturn nonVolatileWrite1Byte(uint8_t *data);
NonVolatileReturn nonVolatileRead1Byte(uint8_t *data);
NonVolatileReturn nonVolatileCAFunctionCall(void);

#endif /* #ifndef STORAGE_COMMON_H_INCLUDED */
