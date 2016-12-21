/** \file
  *
  * \brief Describes functions exported by tz_functions.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef TZ_FUNCTIONS_H_INCLUDED
#define TZ_FUNCTIONS_H_INCLUDED

#include "hwinterface.h"
#include "wallet.h"

typedef struct newWalletHelperStruct
{
    bool use_seed;
    bool make_hidden;
    uint32_t wallet_spec;
    WalletErrors wallet_error;
    /** Random buffer 1. */
    uint8_t random_buffer_0[32];
    /** Random buffer 2. */
    uint8_t random_buffer_1[32];
    /** Random buffer 3. */
    uint8_t random_buffer_2[32];
    /** Random buffer 4. */
    uint8_t random_buffer_3[32];
} newWalletHelper;

AddressHandle makeNewAddressTZ(uint8_t *out_address, PointAffine *out_public_key);
bool generateDeterministic256TestTZ(BigNum256 out, const uint8_t *seed, const uint32_t num);
bool generateDeterministic256TZ(BigNum256 out, const uint8_t *seed, const uint32_t num);
bool getEntropyPoolTZ(uint8_t * out_pool_state);
bool getSeedTZ(uint8_t * seed, bool do_encryption);
bool setEntropyPoolTZ(uint8_t *in_pool_state);
bool TAFunctionCall(void);
NonVolatileReturn flushWalletStorageTZ(void);
NonVolatileReturn readWalletStorageTZ(uint8_t * outputBuffer, uint32_t length, int32_t address);
NonVolatileReturn writeWalletStorageTZ(uint8_t * inputBuffer, uint32_t length, int32_t address);
uint32_t getNumAddressesTZ(void);
uint8_t ecdsaSerialiseTZ(uint8_t *out, const PointAffine *point, const bool do_compress);
void aesXTS(int mode, uint8_t * source, uint32_t source_len, uint8_t * dest, uint32_t dest_len);
void CAFunctionCall(void);
void clearParentPublicKeyCacheTZ(void);
void closeWalletStorageTZ(void);
void createWalletStorageTZ(void);
void deleteWalletStorageTZ(void);
void deriveAndSetEncryptionKeyTZ(const uint8_t *uuid, const uint8_t *password, const unsigned int password_length);
void ecdsaSignTestTZ(BigNum256 r, BigNum256 s, const BigNum256 hash, const BigNum256 private_key);
void generateDeterministicPublicKeyTestTZ(PointAffine *out_public_key, PointAffine *in_parent_public_key, const uint8_t *chain_code, const uint32_t num);
void generateRandomBytesTZ(uint8_t * randomBuffer, uint32_t randomBufferLen);
void hmacSha256TZ(uint8_t *out, const uint8_t *text1, const unsigned int text_length1, const uint8_t *text2, const unsigned int text_length2);
void hmacSha512TZ(uint8_t *out, const uint8_t *text, const unsigned int text_length);
void initialiseTZ(void);
void openWalletStorageTZ(void);
void pbkdf2TZ(uint8_t *out, const uint8_t *password, const unsigned int password_length, const uint8_t *salt, const unsigned int salt_length);
void pointMultiplyTestTZ(PointAffine *p, BigNum256 k);
void read1ByteWalletStorageTZ(uint8_t * outputBuffer);
void ripemd160TZ(uint8_t *message, uint32_t length, uint32_t *h);
void seekWalletStorageTZ(int32_t address);
void setHmacSha256KeyTZ(const uint8_t *key, const unsigned int key_length);
void setHmacSha512KeyTZ(const uint8_t *key, const unsigned int key_length);
void setToGTestTZ(PointAffine *p);
void sha256BeginTZ(int sha_256_op_handler);
void sha256FinishDoubleTZ(uint32_t * hash, uint32_t hash_len, int sha_256_op_handler);
void sha256FinishTZ(uint32_t * hash, uint32_t hash_len, int sha_256_op_handler);
void sha256WriteTZ(uint8_t * text, uint32_t text_size, int sha_256_op_handler);
void terminateTZ(void);
void write1ByteWalletStorageTZ(uint8_t * inputBuffer);
void writeHashToByteArrayTZ(uint8_t *out, uint32_t * hash, bool do_write_big_endian);
WalletErrors changeEncryptionKeyTZ(const uint8_t *password, const unsigned int password_length);
WalletErrors changeWalletNameTZ(uint8_t * new_name);
WalletErrors ecdsaSignTZ(BigNum256 r, BigNum256 s, const BigNum256 hash, AddressHandle ah);
WalletErrors getAddressAndPublicKeyTZ(uint8_t *out_address, PointAffine *out_public_key, AddressHandle ah);
WalletErrors getMasterPublicKeyTZ(PointAffine *out_public_key, uint8_t *out_chain_code);
WalletErrors getPrivateKeyTestTZ(uint8_t *out, AddressHandle ah);
WalletErrors getWalletInfoTZ(uint32_t * out_version, uint8_t * out_name, uint8_t * out_uuid, uint32_t wallet_spec);
WalletErrors initWalletTZ(uint32_t wallet_spec, const uint8_t *password, const unsigned int password_length);
WalletErrors newWalletTZ(uint32_t wallet_spec, uint8_t *name, bool use_seed, uint8_t *seed, bool make_hidden, const uint8_t *password, const unsigned int password_length);
WalletErrors readWalletRecordTZ(WalletRecord * wallet_record, uint32_t address);
WalletErrors uninitWalletTZ(void);
WalletErrors updateWalletVersionTZ(void);
WalletErrors writeCurrentWalletRecordTZ(uint32_t address);

#endif
