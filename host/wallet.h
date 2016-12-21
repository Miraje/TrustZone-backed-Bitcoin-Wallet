/** \file
  *
  * \brief Describes functions, types and constants exported by wallet.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef WALLET_H_INCLUDED
#define WALLET_H_INCLUDED

#include "common.h"
#include "ecdsa.h"
#include "prandom.h"
#include "storage_common.h"

/** Maximum length, in bytes, of the name of a wallet. */
#define NAME_LENGTH			    40

/** Length of the checksum field of a wallet record. This is 32 since SHA-256
  * is used to calculate the checksum and the output of SHA-256 is 32 bytes
  * long. */
#define CHECKSUM_LENGTH			32

/** For functions which return an address handle (#AddressHandle), this is an
  * address handle which indicates that an error occurred. */
#define BAD_ADDRESS_HANDLE		0xFFFFFFFF

/** Absolute maximum number of addresses that can be in a wallet. Practical
  * constraints will probably limit the number of addresses to something lower
  * than this.
  * \warning This value affects all tests that use this variable so for testing
  *          the value is set to 7 otherwise is set to 0xFFFFFFFE
  */
#ifndef TESTING
#define MAX_ADDRESSES     0xFFFFFFFE
#else
#define MAX_ADDRESSES			7
#endif

/** A value which has a one-to-one association with Bitcoin addresses in a
  * given wallet. Address handles are more efficient to deal with than the
  * actual addresses themselves, since address handles are much smaller. */
typedef uint32_t AddressHandle;

/** Possible values for the version field of a wallet record. */
typedef enum WalletVersionEnum
{
	/** Version number which means "nothing here".
	  * \warning This must be 0 or sanitiseNonVolatileStorage() won't clear
	  *          version fields correctly.
	  */
	VERSION_NOTHING_THERE		= 0x00000000,
	/** Version number which means "wallet is not encrypted".
	  * \warning A wallet which uses an encryption key consisting of
	  *          all zeroes (see isEncryptionKeyNonZero()) is considered to be
	  *          unencrypted.
	  */
	VERSION_UNENCRYPTED			= 0x00000002,
	/** Version number which means "wallet is encrypted". */
	VERSION_IS_ENCRYPTED		= 0x00000003
} WalletVersion;

/** Return values for walletGetLastError(). Many other wallet functions will
  * also return one of these values. */
typedef enum WalletErrorsEnum
{
	/** No error actually occurred. */
	WALLET_NO_ERROR				=	0,
	/** Insufficient space on non-volatile storage device. */
	WALLET_FULL					=	1,
	/** No addresses in wallet. */
	WALLET_EMPTY				=	2,
	/** Problem(s) reading from non-volatile storage device. */
	WALLET_READ_ERROR			=	3,
	/** Problem(s) writing to non-volatile storage device. */
	WALLET_WRITE_ERROR			=	4,
	/** There is no wallet at the specified location (or, wrong encryption key
	  * used). */
	WALLET_NOT_THERE			=	6,
	/** The operation requires a wallet to be loaded, but no wallet is
	  * loaded. */
	WALLET_NOT_LOADED			=	7,
	/** Invalid address handle. */
	WALLET_INVALID_HANDLE		=	8,
	/** Backup seed could not be written to specified device. */
	WALLET_BACKUP_ERROR			=	9,
	/** Problem with random number generation system. */
	WALLET_RNG_FAILURE			=	10,
	/** Invalid wallet number specified. */
	WALLET_INVALID_WALLET_NUM	=	11,
	/** The specified operation is not allowed on this type of wallet. */
	WALLET_INVALID_OPERATION	=	12,
	/** A wallet already exists at the specified location. */
	WALLET_ALREADY_EXISTS		=	13,
	/** Bad non-volatile storage address or partition number. */
	WALLET_BAD_ADDRESS			=	14
} WalletErrors;

/** Structure of the unencrypted portion of a wallet record. */
struct WalletRecordUnencryptedStruct
{
    /** Wallet version. Should be one of #WalletVersion. */
    uint32_t version;
    /** Reserved for future use. Set to all zeroes. */
    uint8_t reserved[4];
    /** Name of the wallet. This is purely for the sake of the host; the
      * name isn't ever used or parsed by the functions in this file. */
    uint8_t name[NAME_LENGTH];
    /** Wallet universal unique identifier (UUID). One way for the host to
      * identify a wallet. */
    uint8_t uuid[UUID_LENGTH];
};

/** Structure of the encrypted portion of a wallet record. */
struct WalletRecordEncryptedStruct
{
    /** Number of addresses in this wallet. */
    uint32_t num_addresses;
    /** Random padding. This is random to try and thwart known-plaintext
      * attacks. */
    uint8_t padding[8];
    /** Reserved for future use. Set to all zeroes. */
    uint8_t reserved[4];
    /** Seed for deterministic private key generator. */
    uint8_t seed[SEED_LENGTH];
    /** SHA-256 of everything except this. */
    uint8_t checksum[CHECKSUM_LENGTH];
};

/** Structure of a wallet record. */
typedef struct WalletRecordStruct
{
    /** Unencrypted portion. See #WalletRecordUnencryptedStruct for fields.
      * \warning readWalletRecord() and writeCurrentWalletRecord() both assume
      *          that this occurs before the encrypted portion.
      */
    struct WalletRecordUnencryptedStruct unencrypted;

    /** Encrypted portion. See #WalletRecordEncryptedStruct for fields. */
    struct WalletRecordEncryptedStruct encrypted;
} WalletRecord;

WalletErrors walletGetLastError(void);
WalletErrors changeWalletName(uint8_t *new_name);
WalletErrors initWallet(uint32_t wallet_spec, const uint8_t *password, const unsigned int password_length);
WalletErrors uninitWallet(void);
uint32_t getNumberOfWallets(void);
WalletErrors getWalletInfo(uint32_t *out_version, uint8_t *out_name, uint8_t *out_uuid, uint32_t wallet_spec);
WalletErrors newWallet(uint32_t wallet_spec, uint8_t *name, bool use_seed, uint8_t *seed, bool make_hidden, const uint8_t *password, const unsigned int password_length);
WalletErrors backupWallet(bool do_encrypt, uint32_t destination_device);
WalletErrors deleteWallet(uint32_t wallet_spec);
AddressHandle makeNewAddress(uint8_t *out_address, PointAffine *out_public_key);
uint32_t getNumAddresses(void);
WalletErrors getPrivateKey(uint8_t *out, AddressHandle ah);
WalletErrors getAddressAndPublicKey(uint8_t *out_address, PointAffine *out_public_key, AddressHandle ah);
WalletErrors getMasterPublicKey(PointAffine *out_public_key, uint8_t *out_chain_code);
WalletErrors changeEncryptionKey(const uint8_t *password, const unsigned int password_length);
WalletErrors sanitiseEverything(void);
WalletErrors sanitiseNonVolatileStorage(NVPartitions partition, uint32_t start, uint32_t length);
WalletErrors sanitisePartition(NVPartitions partition);

#endif /* #ifndef WALLET_H_INCLUDED */