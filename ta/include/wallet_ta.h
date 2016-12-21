/** \file
  *
  * \brief Describes the commands ID used in wallet_ta.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef WALLET_TA_H
#define WALLET_TA_H

/** This define is used to indicate that the TEE used is OP-TEE this way it is
  * possible to use code specifically for OP-TEE
  * \waring When changing this variable the #OP_TEE_CA should be changed to.
  */
#define OP_TEE_TA

/** This UUID is generated with uuidgen
  * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define WALLET_TA_UUID { 0xf894e6e0, 0x1215, 0x11e6, \
    { 0x92, 0x81, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

/** The TAFs ID implemented in this TA */
#define CMD_INITIALIZE_HANDLERS             0
#define CMD_FINALIZE_HANDLERS               1
#define CMD_AES_XTS                         2
#define CMD_RIPEMD_160						3
#define CMD_SHA256_INIT                     4
#define CMD_SHA256_UPDATE                   5
#define CMD_SHA256_FINAL                    6
#define CMD_SHA256_FINAL_DOUBLE             7
#define CMD_SET_HMAC_SHA512_KEY             8
#define CMD_HMAC_SHA512                     9
#define CMD_SET_HMAC_SHA256_KEY             10
#define CMD_HMAC_SHA256                     11
#define CMD_CREATE_WALLET_STORAGE           12
#define CMD_OPEN_WALLET_STORAGE             13
#define CMD_CLOSE_WALLET_STORAGE            14
#define CMD_DELETE_WALLET_STORAGE           15
#define CMD_SEEK_WALLET_STORAGE             16
#define CMD_WRITE1_WALLET_STORAGE           17
#define CMD_READ1_WALLET_STORAGE            18
#define CMD_WRITE_WALLET_STORAGE            19
#define CMD_READ_WALLET_STORAGE             20
#define CMD_FLUSH_WALLET_STORAGE            21
#define CMD_GENERATE_PASSWORD_BASED_KEY     22
#define CMD_POINT_MULTIPLY_TEST             23
#define CMD_SET_TO_G_TEST                   24
#define CMD_ECDSA_SERIALISE                 25
#define CMD_ECDSA_SIGN                      26
#define CMD_ECDSA_SIGN_TEST                 27
#define CMD_GENERATE_D_PUB_KEY_TEST         28
#define CMD_CLEAR_PRT_PUB_CACHE             29
#define CMD_GENERATE_RANDOM                 30
#define CMD_GENERATE_D256                   31
#define CMD_GENERATE_D256_TEST              32
#define CMD_UPDATE_WALLET_VERSION           33
#define CMD_WRITE_CURRENT_WALLET            34
#define CMD_DERIVE_AND_SET_ENCRYPTION_KEY   35
#define CMD_GET_NUM_ADDRESSES               36
#define CMD_GET_PRIVATE_KEY_TEST            37
#define CMD_GET_ADDRESS_AND_PUB_KEY         38
#define CMD_GET_MASTER_PUB_KEY              39
#define CMD_CHANGE_ENCRYPTION_KEY           40
#define CMD_READ_WALLET_RECORD              41
#define CMD_INIT_WALLET                     42
#define CMD_UNINIT_WALLET                   43
#define CMD_GET_WALLET_INFO                 44
#define CMD_CHANGE_WALLET_NAME              45
#define CMD_NEW_WALLET                      46
#define CMD_GET_SEED                        47
#define CMD_MAKE_NEW_ADDRESS                48
#define CMD_TEST_CALL                       49
#define CMD_SET_ENTROPY_POOL				50
#define CMD_GET_ENTROPY_POOL                51

/** The storage ID maximum length */
#define STORAGE_ID_LENGTH			        20

/** Number of bytes a SHA-512 hash requires. */
#define SHA512_HASH_LENGTH                  64

/** Number of bytes a SHA-512 hash requires. */
#define SHA256_HASH_LENGTH                  32

/** PBKDF2 is used to derive encryption keys. In order to make brute-force
  * attacks more expensive, this should return a number which is as large as
  * possible, without being so large that key derivation requires an excessive
  * amount of time (> 1 s). This is a platform-dependent function because key
  * derivation speed is platform-dependent.
  * In order to permit key recovery when the number of iterations is unknown,
  * this should be a power of 2. That way, an implementation can use
  * successively greater powers of 2 until the correct number of iterations
  * is found.
  * This variable defines the number of iterations to use in PBKDF2 algorithm.
  */
#define PBKDF2_ITERATIONS			        1024

/** The maximum key size must be between 256 and 1024 bits, multiple of 8 bits */
#define MAX_HMAC_SHA_512_KEY_SIZE           512

/** The maximum key size must be between 192 and 1024 bits, multiple of 8 bits */
#define MAX_HMAC_SHA_256_KEY_SIZE           256

/** Length, in bytes, of the encryption key that setEncryptionKey() and
  * getEncryptionKey() deal with. */
#define WALLET_ENCRYPTION_KEY_LENGTH        32

#endif /*WALLET_TA_H*/
