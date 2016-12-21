/** \file
  *
  * \brief Consists in all the Trusted Application functions that interact with
  * Client Applications.
  *
  * Manages functions related with the initialization and closing of sessions
  * and contexts as well all functions relatively to the wallet storage, wallet
  * functions and cryptographic functions.
  *
  * There are some functions that have suffix's:
  * - '_internal' : Functions that are only used by the TA itself or functions
  *                 that are called by CA and are common to ones used by the TA.
  * - '_test'     : Functions that are only used for testing purposes and are
  *                 really needed for the correct function of the wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#define STR_TRACE_USER_TA "WALLET_TA"

#include "wallet_ta.h"
#include "../host/storage_common.h"
#include "../host/wallet.h"
#include "../host/bignum256.h"
#include "../host/ecdsa.h"
#include "../host/hmac_drbg.h"
#include "../host/tz_functions.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/* TODO CHANGE TO DO HMAC AND SET HTE KEY IN ONE OPERATION */

/** Convert a key size in bits to bytes */
#define KEY_IN_BYTES(key_in_bits) ((key_in_bits + 7) / 8)

/*==============================================================================
	ECDSA CONSTANTS
==============================================================================*/
/** The prime number used to define the prime finite field for secp256k1. */
static const uint8_t secp256k1_p[32] = {
0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_p. */
static const uint8_t secp256k1_complement_p[5] = {
0xd1, 0x03, 0x00, 0x00, 0x01};

/** The order of the base point used in secp256k1. */
const uint8_t secp256k1_n[32] = {
0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_n. */
static const uint8_t secp256k1_complement_n[17] = {
0xbf, 0xbe, 0xc9, 0x2f, 0x73, 0xa1, 0x2d, 0x40,
0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51, 0x45,
0x01};

/** The x component of the base point G used in secp256k1. */
static const uint8_t secp256k1_Gx[32] PROGMEM = {
0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79};

/** The y component of the base point G used in secp256k1. */
static const uint8_t secp256k1_Gy[32] PROGMEM = {
0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c,
0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d,
0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48};

/*==============================================================================
	AES-XTS CONSTANTS
==============================================================================*/
/** An dummy IV used for the AES-XTS. This operation uses an tweak key (among
  * other things) to generate an IV but as the cipher operation still requires
  * an as such is used an 'dummy' IV
  */
static const uint8_t dummy_iv[16] = {
0xaa, 0x79, 0xA9, 0x35, 0x0f, 0x23, 0x76, 0x31,
0x52, 0xe4, 0x81, 0xbe, 0xa7, 0x2f, 0xbb, 0xf8};

/**
 * An 'dummy' key to avoid getting an error if a function tries to
 * encrypt or decrypt before setting a proper key. This key has the size of
 * SHA512_HASH_LENGTH.
 * N92OkEm52gDRdccOGPYoO6p12gu50Cz7OM19HV5v7C4hrc3528s927AHEOP8z1qA
 */
static const uint8_t dummy_key[] = {
0x4e, 0x39, 0x32, 0x4f, 0x6b, 0x45, 0x6d, 0x35,
0x32, 0x67, 0x44, 0x52, 0x64, 0x63, 0x63, 0x4f,
0x47, 0x50, 0x59, 0x6f, 0x4f, 0x36, 0x70, 0x31,
0x32, 0x67, 0x75, 0x35, 0x30, 0x43, 0x7a, 0x37,
0x4f, 0x4d, 0x31, 0x39, 0x48, 0x56, 0x35, 0x76,
0x37, 0x43, 0x34, 0x68, 0x72, 0x63, 0x33, 0x35,
0x32, 0x38, 0x73, 0x39, 0x32, 0x37, 0x41, 0x48,
0x45, 0x4f, 0x50, 0x38, 0x7a, 0x31, 0x71, 0x41};

/*==============================================================================
	RIPE-MD-160 CONSTANTS
==============================================================================*/
/** Selection of message word for main rounds. */
static uint8_t r1[80] PROGMEM = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};

/** Selection of message word for parallel rounds. */
static uint8_t r2[80] PROGMEM = {
5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};

/** Amount of rotate left for main rounds. */
static uint8_t s1[80] PROGMEM = {
11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};

/** Amount of rotate left for parallel rounds. */
static uint8_t s2[80] PROGMEM = {
8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

/** Container for RIPE-MD-160 hash state. */
typedef struct HashStateStruct
{
	/** Where final hash value will be placed. */
	uint32_t h[5];
	/** Current index into HashState#m, ranges from 0 to 15. */
	uint8_t index_m;
	/** Current byte within (32 bit) word of HashState#m.
	  * 0 = LSB, 3 = MSB. */
	uint8_t byte_position_m;
	/** 512 bit message buffer. */
	uint32_t m[16];
	/** Total length of message; updated as bytes are written. */
	uint32_t message_length;
} HashState;

/*==============================================================================
	SESSION DATA STRUCTURE
==============================================================================*/
/** Session data. The Trusted Application can attach an opaque void* context to
  * the session . This context is recalled in all subsequent TA calls within
  * the session.
  */
typedef struct session_data{
	/** It is used to store the storage id. To be used while opening and closing
	  * the storage object. */
	char * storageID;
	/** Stores the size of #storageID . */
	size_t storageIDLen;
	/** Used to indicate if the storage object has already been opened. */
	bool is_storage_open;
	/** Used to indicate if the storage object has already been created. */
	bool is_storage_created;
	/** Is is an object handle which is used to handle the (when) opened wallet
	  * storage object. */
	TEE_ObjectHandle * wallet_handle;
	/** Whether write cache is valid. */
	bool write_cache_valid;
	/** Sector address of current contents of write cache. This is only
	  * well-defined if #write_cache_valid is true. */
	uint32_t write_cache_tag;
	/** Current contents of write cache. This is only well-defined
	  * if #write_cache_valid is true. */
	uint8_t * write_cache;
	/** This will only be valid if a wallet is loaded. It contains a cache of the
	  * currently loaded wallet record. If #wallet_loaded is false (i.e. no wallet
	  * is loaded), then the contents of this variable are undefined. */
	WalletRecord * current_wallet;
	/** This will be false if a wallet is not currently loaded. This will be true
      * if a wallet is currently loaded. */
	bool wallet_loaded;
	/** Whether the currently loaded wallet is a hidden wallet. If
	  * #wallet_loaded is false (i.e. no wallet is loaded), then the meaning of
	  * this variable is undefined. */
	bool is_hidden_wallet;
	/** The address in non-volatile memory where the currently loaded wallet
	  * record is. If #wallet_loaded is false (i.e. no wallet is loaded), then the
	  * contents of this variable are undefined. */
	uint32_t wallet_nv_address;
	/** The parent public key for the BIP 0032 deterministic key generator (see
	  * generateDeterministic256()). The contents of this variable are only valid
	  * if #is_cached_parent_public_key_valid is true.
	  *
	  * generateDeterministic256() could calculate the parent public key each time
	  * a new deterministic key is requested. However, that would slow down
	  * deterministic key generation significantly, as point multiplication would
	  * be required each time a key was requested. So this variable functions as
	  * a cache.
	  * \warning The x and y components are stored in little-endian format.
	  */
	PointAffine cached_parent_public_key;
	/** Specifies whether the contents of #parent_public_key are valid. */
	bool is_cached_parent_public_key_valid;
	/** The prime modulus to operate under.
	  * \warning This must be greater than 2 ^ 255.
	  * \warning The least significant byte of this must be >= 2, otherwise
	  *          bigInvert() will not work correctly.
  	  */
	BigNum256 n;
	/** The 2s complement of #n, with most significant zero bytes removed. */
	uint8_t *complement_n;
	/** The size of #complement_n, in number of bytes. */
	uint8_t size_complement_n;
	/** Check if the current combined encryption key is all zeros. This has
	  * implications for whether a wallet is considered encrypted or
	  * not */
	bool is_encryption_key_non_zero;
	/** Handle for AES encryption operation */
	TEE_OperationHandle * aes_encrypt_op;
	/** Handle for AES decryption operation */
	TEE_OperationHandle * aes_decrypt_op;
	/** Handle for HMAC-512 internal operations */
	TEE_OperationHandle * hmac_op1_internal;
	/** Handle for HMAC-256 internal operations */
	TEE_OperationHandle * hmac_op2_internal;
	/** Handle for HMAC-512 operations */
	TEE_OperationHandle * hmac_op1;
	/** Handle for HMAC-256 operations */
	TEE_OperationHandle * hmac_op2;
	/** Handle for SHA internal operations */
	TEE_OperationHandle * sha_op_internal;
	/** Handle for SHA operations */
	TEE_OperationHandle * sha_op1;
	/** Handle 2 for SHA operations */
	TEE_OperationHandle * sha_op2;
	/** Handle 3 for SHA operations */
	TEE_OperationHandle * sha_op3;
	/** Handle 4 for SHA operations */
	TEE_OperationHandle * sha_op4;
}Session_data;
/*============================================================================*/

/*
 * These declarations are needed because these functions are used in some
 * function prior to their implementation
 */
static TEE_Result set_encryption_key_internal(Session_data * session_data, const uint8_t * in);
static void write_hash_to_byte_array_internal(uint8_t * out, uint32_t * hash, bool do_write_big_endian);
static WalletErrors get_private_key_internal(Session_data * session_data, uint8_t *out, AddressHandle ah);
static void write_u32_little_endian_internal(uint8_t * out, uint32_t in);
static void swap_endian_internal(uint32_t *v);

/*==============================================================================
	ENTRY POINTS
==============================================================================*/
/**
  * Called when the instance of the TA is created. This is the first call in
  * the TA. It is called once and only once in the life time of the Trusted
  * Application instance. If this function fails, the instance is not created.
  * This is the Trusted Application constructor.
  * \return Returns TEE_SUCCESS if the instance is successfully created.
  */
TEE_Result TA_CreateEntryPoint(void)
{
	#ifdef OP_TEE_TA
	DMSG("has been called.");
	#endif
	return TEE_SUCCESS;
}

/**
  * Called when the instance of the TA is destroyed if the TA has not
  * crashed or panicked. This is the last call in the TA. This is the
  * Trusted Application destructor
  */
void TA_DestroyEntryPoint(void)
{
	#ifdef OP_TEE_TA
	DMSG("has been called.");
	#endif
}

/**
  * Called when a new session is opened to the TA. *sess_ctx can be updated
  * with a value to be able to identify this session in subsequent calls to the
  * TA. If this returns an error the connection is rejected and no new session
  * is opened.
  * \param param_types The types of the four parameters.
  * \params A pointer to an array of four parameters.
  * \sess_ctx A pointer to a variable with session context information.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param  params[4], void **sess_ctx)
{
	Session_data * data;

	/* It is not expected any parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
								   	TEE_PARAM_TYPE_NONE,
								   	TEE_PARAM_TYPE_NONE,
								   	TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;

	/*
	 * Allocate memory and initialize the session context structure that
	 * will be used
	 */
	data = TEE_Malloc(sizeof(Session_data), TEE_MALLOC_FILL_ZERO);

	if (data == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Allocate memory for some of the 'data' parameters */
	data->wallet_handle = TEE_Malloc(sizeof(TEE_ObjectHandle),
										TEE_MALLOC_FILL_ZERO);

	data->storageID = TEE_Malloc(STORAGE_ID_LENGTH*sizeof(char),
									TEE_MALLOC_FILL_ZERO);

	data->write_cache = TEE_Malloc(SECTOR_SIZE*sizeof(uint8_t),
								  	TEE_MALLOC_FILL_ZERO);

	data->aes_encrypt_op = TEE_Malloc(sizeof(TEE_OperationHandle),
									 	TEE_MALLOC_FILL_ZERO);

	data->aes_decrypt_op = TEE_Malloc(sizeof(TEE_OperationHandle),
									 	TEE_MALLOC_FILL_ZERO);

	data->hmac_op1_internal = TEE_Malloc(sizeof(TEE_OperationHandle),
							 	TEE_MALLOC_FILL_ZERO);

	data->hmac_op2_internal = TEE_Malloc(sizeof(TEE_OperationHandle),
								TEE_MALLOC_FILL_ZERO);

	data->hmac_op1 = TEE_Malloc(sizeof(TEE_OperationHandle),
							 	TEE_MALLOC_FILL_ZERO);

	data->hmac_op2 = TEE_Malloc(sizeof(TEE_OperationHandle),
								TEE_MALLOC_FILL_ZERO);

	data->sha_op_internal = TEE_Malloc(sizeof(TEE_OperationHandle),
							  	TEE_MALLOC_FILL_ZERO);

	data->sha_op1 = TEE_Malloc(sizeof(TEE_OperationHandle),
							  	TEE_MALLOC_FILL_ZERO);

	data->sha_op2 = TEE_Malloc(sizeof(TEE_OperationHandle),
								TEE_MALLOC_FILL_ZERO);

	data->sha_op3 = TEE_Malloc(sizeof(TEE_OperationHandle),
								TEE_MALLOC_FILL_ZERO);

	data->sha_op4 = TEE_Malloc(sizeof(TEE_OperationHandle),
								TEE_MALLOC_FILL_ZERO);

	data->current_wallet = TEE_Malloc(sizeof(WalletRecord),
										TEE_MALLOC_FILL_ZERO);

	/* Verify if the memory was allocated */
	if (data == NULL
		|| data->wallet_handle == NULL
		|| data->storageID == NULL
		|| data->write_cache == NULL
		|| data->aes_encrypt_op == NULL
		|| data->aes_decrypt_op == NULL
		|| data->hmac_op1_internal == NULL
		|| data->hmac_op2_internal == NULL
		|| data->hmac_op1 == NULL
		|| data->hmac_op2 == NULL
		|| data->sha_op_internal == NULL
		|| data->sha_op1 == NULL
		|| data->sha_op2 == NULL
		|| data->sha_op3 == NULL
		|| data->sha_op4 == NULL
		|| data->current_wallet == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Set to default values other variables of 'data'*/
	data->storageIDLen = 0;
	data->write_cache_tag = 0;
	data->wallet_nv_address = 0;
	data->is_storage_created = false;
	data->is_storage_open = false;
	data->write_cache_valid = false;
	data->is_encryption_key_non_zero = false;
	data->wallet_loaded = false;
	data->is_hidden_wallet = false;

	/* Set 'data' as session context */
	*sess_ctx = data;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	#ifdef OP_TEE_TA
	DMSG("Has been called (session opened with the TA)");
	#endif

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/**
  * Called when a session is closed, sess_ctx hold the value that was
  * assigned by TA_OpenSessionEntryPoint(). Is the responsibility of
  * the Trusted Application to deallocate the session context if memory
  * has been allocated for it.
  * \param sess_ctx The pointer set in the function TA_OpenSessionEntryPoint().
  */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	#ifdef OP_TEE_TA
	DMSG("has been called (session with the TA will be closed.)");
	#endif

	/* Free the memory allocated for the session context */
	TEE_Free(((Session_data *)sess_ctx)->wallet_handle);
	TEE_Free(((Session_data *)sess_ctx)->storageID);
	TEE_Free(((Session_data *)sess_ctx)->write_cache);
	TEE_Free(((Session_data *)sess_ctx)->aes_encrypt_op);
	TEE_Free(((Session_data *)sess_ctx)->aes_decrypt_op);
	TEE_Free(((Session_data *)sess_ctx)->hmac_op1_internal);
	TEE_Free(((Session_data *)sess_ctx)->hmac_op2_internal);
	TEE_Free(((Session_data *)sess_ctx)->hmac_op1);
	TEE_Free(((Session_data *)sess_ctx)->hmac_op2);
	TEE_Free(((Session_data *)sess_ctx)->sha_op_internal);
	TEE_Free(((Session_data *)sess_ctx)->sha_op1);
	TEE_Free(((Session_data *)sess_ctx)->sha_op2);
	TEE_Free(((Session_data *)sess_ctx)->sha_op3);
	TEE_Free(((Session_data *)sess_ctx)->sha_op4);
	TEE_Free(((Session_data *)sess_ctx)->current_wallet);
	TEE_Free(sess_ctx);
}

/*==============================================================================
	INITIALIZATION AND FINALIZATION OF HANDLERS
==============================================================================*/
/**
  * Called to initialize the operation handles allocated in the session context.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result initialize_handlers(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;

	/* It is not expected any parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);
	/* Unused parameters */
	(void)&params;

	/* Check the type of the parameters received */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Allocate the AES XTS encryption operation with the correspondent
	 * handler. The key is a combination of two keys each one with 128 bits
	 * so the final will have the key size of 2*128
	 */
    result = TEE_AllocateOperation(session_data->aes_encrypt_op,
    								TEE_ALG_AES_XTS,
    								TEE_MODE_ENCRYPT,
    								(uint32_t)(2*128));

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for AES-XTS encryption operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /*
     * Allocate the AES XTS decryption operation with the correspondent
     * handler. The key is a combination of two keys each one with 128 bits
	 * so the final will have the key size of 2*128
	 */
    result = TEE_AllocateOperation(session_data->aes_decrypt_op,
    								TEE_ALG_AES_XTS,
    								TEE_MODE_DECRYPT,
    								(uint32_t)(2*128));

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for AES-XTS decryption operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Seth the 'dummy' key as encryption key */
    result = set_encryption_key_internal(session_data, dummy_key);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to set the keys for AES-XTS: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the HMAC-SHA-512 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->hmac_op1_internal,
    								TEE_ALG_HMAC_SHA512,
    								TEE_MODE_MAC,
    								(uint32_t)MAX_HMAC_SHA_512_KEY_SIZE);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for HMAC-SHA512 internal operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the HMAC-SHA-256 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->hmac_op2_internal,
    								TEE_ALG_HMAC_SHA256,
    								TEE_MODE_MAC,
    								(uint32_t)MAX_HMAC_SHA_256_KEY_SIZE);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for HMAC-SHA256 internal operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

	/* Allocate the HMAC-SHA-512 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->hmac_op1,
    								TEE_ALG_HMAC_SHA512,
    								TEE_MODE_MAC,
    								(uint32_t)MAX_HMAC_SHA_512_KEY_SIZE);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for HMAC-SHA512 operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the HMAC-SHA-256 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->hmac_op2,
    								TEE_ALG_HMAC_SHA256,
    								TEE_MODE_MAC,
    								(uint32_t)MAX_HMAC_SHA_256_KEY_SIZE);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for HMAC-SHA256 operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the SHA-256 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->sha_op_internal,
    								TEE_ALG_SHA256,
    								TEE_MODE_DIGEST,
    								(uint32_t)0);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for SHA-256 internal operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the SHA-256 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->sha_op1,
    								TEE_ALG_SHA256,
    								TEE_MODE_DIGEST,
    								(uint32_t)0);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler for SHA-256 operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the second SHA-256 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->sha_op2,
    								TEE_ALG_SHA256,
    								TEE_MODE_DIGEST,
    								(uint32_t)0);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler 2 for SHA-256 operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the third SHA-256 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->sha_op3,
    								TEE_ALG_SHA256,
    								TEE_MODE_DIGEST,
    								(uint32_t)0);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler 3 for SHA-256 operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Allocate the forth SHA-256 operation with the correspondent handler */
    result = TEE_AllocateOperation(session_data->sha_op4,
    								TEE_ALG_SHA256,
    								TEE_MODE_DIGEST,
    								(uint32_t)0);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate the handler 4 for SHA-256 operation: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /* Resources cleanup */
    cleanup1:
   		return result;
}

/**
  * Called to finalize the operation handles allocated in the session context.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS if TEE_FreeOperation does not fail.
  */
static TEE_Result finalize_handlers(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);
	/* Unused parameters */
	(void)&params;

	/* Check the type of the parameters received */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Free the operations allocated */
	TEE_FreeOperation(*(session_data->aes_encrypt_op));
	TEE_FreeOperation(*(session_data->aes_decrypt_op));
	TEE_FreeOperation(*(session_data->hmac_op1_internal));
	TEE_FreeOperation(*(session_data->hmac_op2_internal));
	TEE_FreeOperation(*(session_data->hmac_op1));
	TEE_FreeOperation(*(session_data->hmac_op2));
	TEE_FreeOperation(*(session_data->sha_op_internal));
	TEE_FreeOperation(*(session_data->sha_op1));
	TEE_FreeOperation(*(session_data->sha_op2));
	TEE_FreeOperation(*(session_data->sha_op3));
	TEE_FreeOperation(*(session_data->sha_op4));

   	return TEE_SUCCESS;
}

/*==============================================================================
	AES FUNCTIONS

	In the original wallet code it was used AES-XEX but as said in the file
	"xex.h" (from the original wallet code):
	"
	Using AES in XEX mode, with ciphertext stealing and with independent keys
	is sometimes called "XTS-AES". But as long as the length of a wallet record
	(#WALLET_RECORD_LENGTH) is a multiple of 16 bytes, ciphertext stealing is
	not necessary. Thus the use of AES in XEX mode here is identical in
	operation to XTS-AES.
    As in XTS-AES, independent "tweak" and "encryption" keys are used. This
    means that the combined key is 256 bits in length. But since this 256 bit
    key is composed of two 128 bit keys, the final cipher still only
    has 128 bits of security.
    "
    And as the GlobalPlatform hasn't specified the XEX mode the mode used is XTS.
==============================================================================*/
/** Set the AES-XTS combined encryption key.
  * \param session_data The pointer set in the function TA_OpenSessionEntryPoint().
  * \param in A #WALLET_ENCRYPTION_KEY_LENGTH byte array specifying the
  *           combined encryption key to use in XTS encryption/decryption
  *           operations.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result set_encryption_key_internal(Session_data * session_data, const uint8_t * in)
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle transient_key1 = TEE_HANDLE_NULL;
	TEE_ObjectHandle transient_key2 = TEE_HANDLE_NULL;
	TEE_Attribute key_attribute1;
	TEE_Attribute key_attribute2;
	uint8_t r;
	uint8_t i;

	/* Allocate a transient object to store the encryption key */
	result = TEE_AllocateTransientObject(
					TEE_TYPE_AES,
					(uint32_t)128, 			/* Max key size expected */
					&transient_key1);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate transient object for key 1: 0x%x", result);
    	#endif
    	goto cleanup1;
	}

	/*
	 * Usually the 'in' parameter has SHA512_HASH_LENGTH (64 bytes) but as we
	 * are using the AES-XTS where each key has 128 bits we will only use the
	 * first 32 bytes
	 */

	/* Initialize an attribute that will contain the encryption key */
	TEE_InitRefAttribute(
    		&key_attribute1,
    		TEE_ATTR_SECRET_VALUE, 		/* Identifier of the attribute */
    		(uint8_t*)in, 				/* Key */
			16);

	/*
	 * Populate the transient object with the attribute which have the
	 * encryption key
	 */
	result = TEE_PopulateTransientObject(transient_key1, &key_attribute1, 1);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to populate transient key 1: 0x%x", result);
    	#endif
    	goto cleanup2;
	}

	/* Allocate a transient object to store the tweak key */
	result = TEE_AllocateTransientObject(
					TEE_TYPE_AES,
					(uint32_t)128, 			/* Max key size expected */
					&transient_key2);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate transient key 2: 0x%x", result);
    	#endif
    	goto cleanup2;
	}

	/* Initialize an attribute that will contain the tweak key */
	TEE_InitRefAttribute(
    		&key_attribute2,
    		TEE_ATTR_SECRET_VALUE, 			/* Identifier of the attribute */
    		(uint8_t*)&(in[16]), 			/* Key */
			16);

	/*
	 * Populate the transient object with the attribute which have the tweak key
	 */
	result = TEE_PopulateTransientObject(transient_key2, &key_attribute2, 1);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to populate transient for key 2: 0x%x", result);
    	#endif
    	goto cleanup3;
	}

	/* Set the keys for the AES encryption operation */
	result = TEE_SetOperationKey2(*(session_data->aes_encrypt_op),
									transient_key1,
									transient_key2);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to set key for AES encryption operation: 0x%x", result);
    	#endif
    	goto cleanup3;
	}

	/* Set the keys for the AES decryption operation */
	result = TEE_SetOperationKey2(*(session_data->aes_decrypt_op),
									transient_key1,
									transient_key2);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to set key for AES decryption operation: 0x%x", result);
    	#endif
    	goto cleanup3;
	}

	/*
	 * Set the is_encryption_key_non_zero to true if the encryption key is not
	 * made up of all zeros or false if the encryption key is made up of all
	 * zeros.
	 */
	r = 0;

	for (i = 0; i < 16; i++)
	{
		r |= in[i];
		r |= in[i+16];
	}

	if (r != 0)
		session_data->is_encryption_key_non_zero = true;
	else
		session_data->is_encryption_key_non_zero = false;

	/*
	 * Cleanup resources. The transient keys are no longer needed as they were
	 * already associated with the operations
	 */
	cleanup3:
		TEE_FreeTransientObject(transient_key2);
	cleanup2:
		TEE_FreeTransientObject(transient_key1);
	cleanup1:
		return result;
}

/** Performs the encryption/decryption of data using AES-XTS.
  * \param session_data A data pointer to a session context.
  * \param mode To decrypt, use TEE_MODE_ENCRYPT. To encrypt, use TEE_MODE_DECRYPT.
  * \param src_data A pointer to an array which contain the data to decrypt or encrypt.
  * \param src_len Size of the array pointed by src_data.
  * \param dest_data A pointer to an array which contain the data decrypted or encrypted.
  * \param dest_len Size of the array pointed by dest_data.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result aes_xts_internal(Session_data * session_data, TEE_OperationMode mode, uint8_t * src_data, uint32_t src_len, uint8_t * dest_data, uint32_t dest_len)
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t written_bytes = dest_len;

	/* If it is an encryption operation */
	if (mode == TEE_MODE_ENCRYPT)
	{
		/* Initialize the cipher operation */
		TEE_CipherInit(*(session_data->aes_encrypt_op),
						(uint8_t*)dummy_iv,
						(uint32_t)16);

		/*
		 * Here we could do TEE_CipherUpdate() but as we will encrypt in only
		 * one operation it will not be needed
		 */

		/* Finalize cipher operation */
		result = TEE_CipherDoFinal(*(session_data->aes_encrypt_op),
									(uint8_t*)src_data, src_len,
									(uint8_t*)dest_data,
									&written_bytes);

		if (result != TEE_SUCCESS)
		{
			#ifdef OP_TEE_TA
			DMSG("Failed to finalize the ciphering operation : 0x%x", result);
    		#endif
			goto cleanup1;
		}

		/* Confirm that all bytes were written */
		if (written_bytes != dest_len)
		{
			#ifdef OP_TEE_TA
			DMSG("Cipher operation didn't encrypt all the bytes requested : 0x%x", result);
    		#endif

			/*
			 * Here the return should be return TEE_ERROR_EXCESS_DATA;
			 * but as this will be treated as an error by the CA the most safest
			 * way is to set as TEE_ERROR_BAD_STATE to signal an operation that
			 * failed but without the needing to exit the program
			 */
			return TEE_ERROR_BAD_STATE;
		}
	}
	/* If it is an decryption operation */
	else if (mode == TEE_MODE_DECRYPT)
	{
		/* Initialize the cipher operation */
		TEE_CipherInit(*(session_data->aes_decrypt_op),
						(uint8_t*)dummy_iv,
						(uint32_t)16);

		/*
		 * Here we could do TEE_CipherUpdate() but as we will encrypt in only
		 * one operation it will not be needed
		 */

		/* Finalize cipher operation */
		result = TEE_CipherDoFinal(*(session_data->aes_decrypt_op),
									(uint8_t*)src_data,
									src_len,
									(uint8_t*)dest_data,
									&written_bytes);

		if (result != TEE_SUCCESS)
		{
			#ifdef OP_TEE_TA
			DMSG("Cipher operation Do final failed : 0x%x", result);
			#endif
			goto cleanup1;
		}

		/* Confirm that all bytes were written */
		if (written_bytes != dest_len)
		{
			#ifdef OP_TEE_TA
			DMSG("Cipher operation didn't decrypt all the bytes requested : 0x%x", result);
			#endif

			/*
			 * Here the return should be return TEE_ERROR_EXCESS_DATA;
			 * but as this will be treated as an error by the CA the most safest
			 * way is to set as TEE_ERROR_BAD_STATE to signal an operation that
			 * failed but without the needing to exit the program
			 */
			return TEE_ERROR_BAD_STATE;
		}
	}
	else
		return TEE_ERROR_BAD_PARAMETERS;

	cleanup1:
		return result;
}

/** Wrapper of aes_xts_internal() for a command of the CA.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result aes_xts(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	TEE_OperationMode mode;

	/*
     * Expected:
     * [IO]  params[0].memref.buffer -> Source data to encrypt or decrypt.
     * [IO]  params[0].memref.size   -> Size of the source data.
     * [IO]  params[1].memref.buffer -> Destination data of the encryption or
     *                                  decryption.
     * [IO]  params[1].memref.size   -> Size of destination data.
     * [IN]  params[2].value.a       -> Mode of operation (encryption or
     *                                  decryption).
     */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INOUT,
							TEE_PARAM_TYPE_MEMREF_INOUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
	 || params[0].memref.buffer == NULL
	 || params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the operation mode */
	if (params[2].value.a == (uint32_t)0)
		mode = TEE_MODE_ENCRYPT;
	else
		mode = TEE_MODE_DECRYPT;

	/* Call the internal function to perform the operation */
	result = aes_xts_internal(
				session_data,
				mode,
				(uint8_t*)(params[0].memref.buffer),
				(uint32_t)(params[0].memref.size),
				(uint8_t*)(params[1].memref.buffer),
				(uint32_t)(params[1].memref.size));

	return result;
}

/*==============================================================================
	RIPE-MD-160 OPERATIONS
==============================================================================*/
/** Cyclic shift left (rotate left).
  * \param x The integer to rotate left.
  * \param n Number of times to rotate left.
  * \return The rotated integer.
  */
static uint32_t rol(uint32_t x, uint8_t n)
{
	return (x << n) | (x >> (32 - n));
}

/** First non-linear (at bit level) function.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t f0(uint32_t x, uint32_t y, uint32_t z)
{
	return x ^ y ^ z;
}

/** Second non-linear (at bit level) function.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t f1(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) | (~x & z);
}

/** Third non-linear (at bit level) function.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t f2(uint32_t x, uint32_t y, uint32_t z)
{
	return (x | ~y) ^ z;
}

/** Fourth non-linear (at bit level) function.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t f3(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & z) | (y & ~z);
}

/** Fifth non-linear (at bit level) function.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t f4(uint32_t x, uint32_t y, uint32_t z)
{
	return x ^ (y | ~z);
}

/** Update hash value based on the contents of a full message buffer.
  * \param hs The hash state to update.
  */
static void ripemd_160_block_internal(HashState *hs)
{
	uint32_t A1, B1, C1, D1, E1;
	uint32_t A2, B2, C2, D2, E2;
	uint32_t K1, K2, R1, R2;
	uint32_t T;
	uint8_t fn_selector;
	uint8_t j;

	A1 = hs->h[0];
	A2 = A1;
	B1 = hs->h[1];
	B2 = B1;
	C1 = hs->h[2];
	C2 = C1;
	D1 = hs->h[3];
	D2 = D1;
	E1 = hs->h[4];
	E2 = E1;

	for (j = 0; j < 80; j++)
	{
		fn_selector = (uint8_t)(j >> 4);

		switch(fn_selector)
		{
			case 0:
				R1 = f0(B1, C1, D1);
				R2 = f4(B2, C2, D2);
				K1 = 0x00000000;
				K2 = 0x50a28be6;
				break;
			case 1:
				R1 = f1(B1, C1, D1);
				R2 = f3(B2, C2, D2);
				K1 = 0x5a827999;
				K2 = 0x5c4dd124;
				break;
			case 2:
				R1 = f2(B1, C1, D1);
				R2 = f2(B2, C2, D2);
				K1 = 0x6ed9eba1;
				K2 = 0x6d703ef3;
				break;
			case 3:
				R1 = f3(B1, C1, D1);
				R2 = f1(B2, C2, D2);
				K1 = 0x8f1bbcdc;
				K2 = 0x7a6d76e9;
				break;
			default:
				R1 = f4(B1, C1, D1);
				R2 = f0(B2, C2, D2);
				K1 = 0xa953fd4e;
				K2 = 0x00000000;
				break;
		}

		T  = rol(A1 + R1 + hs->m[LOOKUP_BYTE(r1[j])] + K1, LOOKUP_BYTE(s1[j])) + E1;
		A1 = E1;
		E1 = D1;
		D1 = rol(C1, 10);
		C1 = B1;
		B1 = T;

		T  = rol(A2 + R2 + hs->m[LOOKUP_BYTE(r2[j])] + K2, LOOKUP_BYTE(s2[j])) + E2;
		A2 = E2;
		E2 = D2;
		D2 = rol(C2, 10);
		C2 = B2;
		B2 = T;
	}

	T = hs->h[1] + C1 + D2;
	hs->h[1] = hs->h[2] + D1 + E2;
	hs->h[2] = hs->h[3] + E1 + A2;
	hs->h[3] = hs->h[4] + A1 + B2;
	hs->h[4] = hs->h[0] + B1 + C2;
	hs->h[0] = T;
}

/** Begin calculating hash for new message.
  * \param hs The hash state to initialize.
  */
static void ripemd_160_begin_internal(HashState *hs)
{
	hs->message_length = 0;
	hs->h[0] = 0x67452301;
	hs->h[1] = 0xefcdab89;
	hs->h[2] = 0x98badcfe;
	hs->h[3] = 0x10325476;
	hs->h[4] = 0xc3d2e1f0;
	hs->index_m = 0;
	hs->byte_position_m = 0;
	TEE_MemFill((uint32_t*)(hs->m), 0, (uint32_t)sizeof(hs->m));
}

/** Add one more byte to the message buffer and call ripemd_160_block_internal()
  * if the message buffer is full.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialized using ripemd_160_begin_internal() at some time in the
  *           past.
  * \param byte The byte to add.
  */
static void ripemd_160_write_byte_internal(HashState *hs, uint8_t byte)
{
	uint8_t pos; /* corrected for endianness */

	/* Total size of the message processed */
	hs->message_length++;

	/* Get the byte position within 32-bit word */
	pos = (uint8_t)(3 - hs->byte_position_m);

	/* Shift the byte accordingly to the position */
	switch (pos)
	{
		case 0:
			hs->m[hs->index_m] |= ((uint32_t)byte << 24);
			break;
		case 1:
			hs->m[hs->index_m] |= ((uint32_t)byte << 16);
			break;
		case 2:
			hs->m[hs->index_m] |= ((uint32_t)byte << 8);
			break;
		case 3:
		default:
			hs->m[hs->index_m] |= ((uint32_t)byte);
			break;
	}

	if (hs->byte_position_m == 3)
		hs->index_m++;

	hs->byte_position_m = (uint8_t)((hs->byte_position_m + 1) & 3);

	/* Block of 16B is full, clean the message parameters */
	if (hs->index_m == 16)
	{
		ripemd_160_block_internal(hs);

		hs->index_m = 0;
		hs->byte_position_m = 0;
		TEE_MemFill((uint32_t*)(hs->m), 0, (uint32_t)sizeof(hs->m));
	}
}

/** Finalize the hashing of a message by writing appropriate padding and
  * length bytes.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialized using ripemd_160_begin_internal() at some time in the
  *           past.
  */
static void ripemd_160_finish_internal(HashState *hs)
{
	uint32_t length_bits;
	uint8_t i;
	uint8_t buffer[8];

	/*
	 * Subsequent calls to ripemd_160_write_byte_internal() will keep incrementing
	 * message_length, so the calculation of length (in bits) must be
	 * done before padding.
	 */
	length_bits = hs->message_length << 3;

	/*
	 * Pad using a 1 bit followed by enough 0 bits to get the message buffer
	 * to exactly 448 bits full.
	 */
	ripemd_160_write_byte_internal(hs, (uint8_t)0x80);

	while ((hs->index_m != 14) || (hs->byte_position_m != 0))
		ripemd_160_write_byte_internal(hs, 0);

	/* Write 64 bit length (in bits). */
	TEE_MemFill((uint8_t*)buffer, 0, (uint32_t)8);

	write_u32_little_endian_internal(&(buffer[0]), length_bits);

	for (i = 0; i < 8; i++)
		ripemd_160_write_byte_internal(hs, buffer[i]);

	for	(i = 0; i < 5; i++)
		swap_endian_internal(&(hs->h[i]));
}

/** Calculate RIPEMD-160 hash of a message. The result is returned in #h.
  * \param message The message to calculate the hash of. This must be a byte
  *                array of the size specified by length.
  * \param length The length (in bytes) of the message.
  */
static void ripemd_160_internal(uint8_t *message, uint32_t length, uint32_t *h)
{
	uint32_t i;
	HashState hs;

	ripemd_160_begin_internal(&hs);

	for (i = 0; i < length; i++)
		ripemd_160_write_byte_internal(&hs, message[i]);

	ripemd_160_finish_internal(&hs);

	TEE_MemMove((uint32_t*)h, (uint32_t*)(hs.h), (uint32_t)20);
}

/** Wrapper of ripemd_160_internal() for a command of the CA.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result ripemd_160(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
     * Expected:
     * [IN]  params[0].memref.buffer -> Source data to hash.
     * [IN]  params[0].memref.size   -> Size of the source data.
     * [OUT] params[1].memref.buffer -> Destination data of the hash.
     * [OUT]  params[1].memref.size   -> Size of destination data.
     */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
	 || params[0].memref.buffer == NULL
	 || params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)&session_data;

	/* Call the internal function to perform the operation */
	ripemd_160_internal(
			(uint8_t*)(params[0].memref.buffer),
			(uint32_t)(params[0].memref.size),
			(uint32_t*)(params[1].memref.buffer));

	return result;
}

/*==============================================================================
	SHA-256 OPERATIONS
==============================================================================*/
/** Convert an byte array with 32 positions to a 32 bit unsigned integer array
  * with 8 position in big-endian format.
  * \param array_src The source byte array.
  * \param array_dest The destine byte array.
  */
static void convert_from8_to32_BE_internal(uint8_t * array_src, uint32_t * array_dest)
{
    uint8_t i;

    for (i = 0; i < 32; i += 4)
    {
    	array_dest[i/4] = (array_src[i] << 24)
    						| (array_src[i+1] << 16)
    						| (array_src[i+2] << 8)
    						| (array_src[i+3]);
    }
}

/** Resets the operation state before initialization BUT after the key has been
  * set.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result sha256_init(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	int sha_op_selc;
	uint32_t exp_param_types;

	/*
     * Expected:
     * [IN]  params[0].value.a -> SHA operation handler number.
     */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (exp_param_types != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get the desired SHA-256 operation handle number */
	sha_op_selc = (int)(params[0].value.a);

	/* Reset operation accordingly */
	switch (sha_op_selc)
    {
        case 1:
            TEE_ResetOperation(*(session_data->sha_op1));
            break;
        case 2:
            TEE_ResetOperation(*(session_data->sha_op2));
            break;
        case 3:
            TEE_ResetOperation(*(session_data->sha_op3));
            break;
        case 4:
            TEE_ResetOperation(*(session_data->sha_op4));
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    };

	return TEE_SUCCESS;
}

/** Accumulates message data for hashing (SHA-256). The message does not have
  * to be block aligned. Subsequent calls to this function are possible.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result sha256_update(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	int sha_op_selc;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> Text.
	 * [IN]  params[0].memref.size   -> Length of the text.
	 * [IN]  params[1].value.a -> SHA operation handler number.
	 */
	 exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (exp_param_types != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get the desired SHA-256 operation handle number */
	sha_op_selc = (int)(params[1].value.a);

	/* Execute the operation accordingly */
	switch (sha_op_selc)
    {
        case 1:
            TEE_DigestUpdate(*(session_data->sha_op1),
					(uint8_t*)(params[0].memref.buffer),
					(uint32_t)(params[0].memref.size));
            break;
        case 2:
            TEE_DigestUpdate(*(session_data->sha_op2),
					(uint8_t*)(params[0].memref.buffer),
					(uint32_t)(params[0].memref.size));
            break;
        case 3:
            TEE_DigestUpdate(*(session_data->sha_op3),
					(uint8_t*)(params[0].memref.buffer),
					(uint32_t)(params[0].memref.size));
            break;
        case 4:
            TEE_DigestUpdate(*(session_data->sha_op4),
					(uint8_t*)(params[0].memref.buffer),
					(uint32_t)(params[0].memref.size));
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    };

	return TEE_SUCCESS;
}

/** Finalizes the message digest operation and produces the message hash (SHA-256).
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result sha256_final(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	int sha_op_selc;
	uint32_t exp_param_types;
	uint32_t written_hash_length;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Hash buffer.
	 * [OUT] params[0].memref.size   -> Length of the hash buffer.
	 * [IN]  params[1].value.a -> SHA operation handler number.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (exp_param_types != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	written_hash_length = (uint32_t)params[0].memref.size;

	/* Get the desired SHA-256 operation handle number */
	sha_op_selc = (int)(params[1].value.a);

	/* Execute the operation accordingly */
	switch (sha_op_selc)
    {
        case 1:
            result = TEE_DigestDoFinal(*(session_data->sha_op1),
								NULL,
								0,
								(uint8_t*)(params[0].memref.buffer),
								&written_hash_length);
            break;
        case 2:
            result = TEE_DigestDoFinal(*(session_data->sha_op2),
								NULL,
								0,
								(uint8_t*)(params[0].memref.buffer),
								&written_hash_length);
            break;
        case 3:
            result = TEE_DigestDoFinal(*(session_data->sha_op3),
								NULL,
								0,
								(uint8_t*)(params[0].memref.buffer),
								&written_hash_length);
            break;
        case 4:
            result = TEE_DigestDoFinal(*(session_data->sha_op4),
								NULL,
								0,
								(uint8_t*)(params[0].memref.buffer),
								&written_hash_length);
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    };

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to finalize the hashing operation (SHA-256): 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Update size to the one actually hashed */
	params[0].memref.size = (uint32_t)written_hash_length;

	cleanup1:
		return result;
}

/** Just like sha256_final() except this does a double SHA-256 hash. A
  * double SHA-256 hash is sometimes used in the Bitcoin protocol.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result sha256_final_double(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_OperationHandle * sha_op_handle;
	int sha_op_selc;
	uint32_t exp_param_types;
	uint32_t written_hash_length;
	uint32_t hash_u32[8];
	uint8_t * hash_u8;
	uint8_t temp[32];

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Hash buffer.
	 * [OUT] params[0].memref.size   -> Length of the hash buffer.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (exp_param_types != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get the desired SHA-256 operation handle number */
	sha_op_selc = (int)(params[1].value.a);

	/* Choose the operation handle accordingly */
	switch (sha_op_selc)
    {
        case 1:
            sha_op_handle = session_data->sha_op1;
            break;
        case 2:
            sha_op_handle = session_data->sha_op2;
            break;
        case 3:
            sha_op_handle = session_data->sha_op3;
            break;
        case 4:
            sha_op_handle = session_data->sha_op4;
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    };

	hash_u8 = (uint8_t*)(params[0].memref.buffer);
	written_hash_length = (uint32_t)params[0].memref.size;

	/* Do the first digest final */
	result = TEE_DigestDoFinal(*sha_op_handle, NULL, 0, (uint8_t*)hash_u8, &written_hash_length);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to finalize the hashing operation (SHA-256): 0x%x", result);
		#endif
		goto cleanup1;
	}

	convert_from8_to32_BE_internal(hash_u8, hash_u32);

	write_hash_to_byte_array_internal(temp, hash_u32, true);

	/* Initialize the operation */
	TEE_ResetOperation(*sha_op_handle);

	/* Update the content to hash */
	TEE_DigestUpdate(*sha_op_handle, (uint8_t*)temp, (uint32_t)32);

	/* Do the last digest final */
	result = TEE_DigestDoFinal(*sha_op_handle, NULL, 0, (uint8_t*)hash_u8, &written_hash_length);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to finalize the hashing operation (SHA-256): 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Update size to the one actually hashed */
	params[0].memref.size = (uint32_t)written_hash_length;

	cleanup1:
		return result;
}

/** Resets the operation state before initialization BUT after the key has been
  * set. It is to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  */
static void sha256_init_internal(Session_data * session_data)
{
	TEE_ResetOperation(*(session_data->sha_op_internal));
}

/** Accumulates message data for hashing (SHA-256). The message does not have
  * to be block aligned. Subsequent calls to this function are possible.  It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param text The data to be hashed.
  * \param text_size Size of text.
  */
static void sha256_update_internal(Session_data * session_data, uint8_t * text, uint32_t text_size)
{
	TEE_DigestUpdate(*(session_data->sha_op_internal), (uint8_t*)text, text_size);
}

/** Finalizes the message digest operation and produces the message hash
  * (SHA-256). It is to be used internally (only by the functions of the TA
  * itself).
  * \param session_data A data pointer to a session context.
  * \param hash Output buffer filled with the message hash.
  * \param hash_len Length of hash.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result sha256_final_internal(Session_data * session_data, uint32_t * hash, uint32_t hash_len)
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t written_hash_length = hash_len;
	uint8_t h[32];

	result = TEE_DigestDoFinal(*(session_data->sha_op_internal), NULL, 0, (uint8_t*)h, &written_hash_length);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to finalize the hashing operation (SHA-256): 0x%x", result);
		#endif
		goto cleanup1;
	}

	/*
	 * As the output need to be in an array of 32 bit unsigned integer in
	 * big-endian format it is needed a conversion
	 */
	convert_from8_to32_BE_internal(h, hash);

	cleanup1:
		return result;
}

/*==============================================================================
	HMAC-256 AND HMAC-512 OPERATIONS
==============================================================================*/
/**
  * Wrapper of the set_hmac_sha512_key_internal() for a CA command.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result set_hmac_sha512_key(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle hmac_key = TEE_HANDLE_NULL;
	TEE_Attribute key_attribute;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> Key of the HMAC-SHA-512 operation
	 * [IN]  params[0].memref.size   -> Size of the key.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL )
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate an transient object that will held the key */
	result = TEE_AllocateTransientObject(
					TEE_TYPE_HMAC_SHA512,
					(uint32_t)MAX_HMAC_SHA_512_KEY_SIZE,
					&hmac_key);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate transient key for HMAC-SHA-512 operations: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /*
     * As the key is defined by one attribute parameter it is needed to create an
     * attribute with it
     */
    TEE_InitRefAttribute(
    		&key_attribute,
    		TEE_ATTR_SECRET_VALUE,
    		(uint8_t*)(params[0].memref.buffer),
    		(unsigned int)(params[0].memref.size));

    /* Now use the attribute to set the key into the transient object */
	result = TEE_PopulateTransientObject(hmac_key, &key_attribute, 1);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to populate transient key for HMAC-SHA-512 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Finally, set the operation key */
   	result = TEE_SetOperationKey(*(session_data->hmac_op1), hmac_key);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed set operation key for HMAC-SHA-512 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Resources cleanup */
    cleanup2:
    	/*
    	 * Free the key object as the operation is already set it is no longer
    	 * needed
    	 */
    	TEE_FreeTransientObject(hmac_key);
	cleanup1:
		return result;
}

/**
  * Executes the HMAC-SHA-512 operation.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result hmac_sha512(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint32_t hash_length;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer to write the resulted hash.
	 * [OUT] params[0].memref.size   -> Size of of the buffer.
	 * [IN]  params[1].memref.buffer -> Input buffer with the text to be hashed.
	 * [IN]  params[1].memref.size   -> Size of the input buffer.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Initialize MAC operation */
    TEE_MACInit(*(session_data->hmac_op1), NULL, 0);

    /*
     * Here we could call TEE_MACUpdate but as we will use just one input
     * message it is not needed instead we could use TEE_MACComputeFinal to
     * finalize and accumulate the data.
     */

    /* Define the hash size */
    hash_length = (uint32_t)(params[0].memref.size);

    /*
     * Finalize the MAC operation with a last chunk of message, and computes
     * the MAC
     */
    result = TEE_MACComputeFinal(
    				*(session_data->hmac_op1),
    				(uint8_t*)(params[1].memref.buffer),
    				(uint32_t)(params[1].memref.size),
    				(uint8_t*)(params[0].memref.buffer),
    				&hash_length);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to finalize HMAC-SHA-512 operation: 0x%x", result);
    	#endif
    }

	return result;
}

/**
  * Sets the key for the HMAC-SHA-512 operation. It is to be used internally
  * (only by the functions of the TA  itself).
  * \param session_data A data pointer to a session context.
  * \param key A byte array containing the key to use in the HMAC-SHA512
  *            calculation. The key can be of any length.
  * \param key_length The length, in bytes, of the key.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result set_hmac_sha512_key_internal(Session_data * session_data, const uint8_t *key, const unsigned int key_length)
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle hmac_key = TEE_HANDLE_NULL;
	TEE_Attribute key_attribute;

	/* Allocate an transient object that will held the key */
	result = TEE_AllocateTransientObject(
					TEE_TYPE_HMAC_SHA512,
					MAX_HMAC_SHA_512_KEY_SIZE,
					&hmac_key);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate A transient key for HMAC-SHA-512 operations: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /*
     * As the key is defined by one attribute parameter it is needed to create
     * an attribute with it
     */
    TEE_InitRefAttribute(
    		&key_attribute,
    		TEE_ATTR_SECRET_VALUE,
    		(uint8_t*)key,
    		(unsigned int)key_length);

    /* Now use the attribute the set the key into the transient object */
	result = TEE_PopulateTransientObject(hmac_key, &key_attribute, 1);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to populate the transient key for HMAC-SHA-512 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Finally, set the operation key */
   	result = TEE_SetOperationKey(*(session_data->hmac_op1_internal), hmac_key);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed set operation key for HMAC-SHA-512 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Resources cleanup */
    cleanup2:
    	/*
    	 * Free the key object as the operation is already set it is no longer
    	 * needed
    	 */
    	TEE_FreeTransientObject(hmac_key);
	cleanup1:
		return result;
}

/**
  * Executes the HMAC-SHA-512 operation.
  * \param session_data A data pointer to a session context.
  * \param out A byte array where the HMAC-SHA512 hash value will be written.
  *            This must have space for #SHA512_HASH_LENGTH bytes.
  * \param text A byte array containing the message to use in the HMAC-SHA512
  *             calculation. The message can be of any length.
  * \param text_length The length, in bytes, of the message.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result hmac_sha512_internal(Session_data * session_data, uint8_t *out, const uint8_t *text, const unsigned int text_length)
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t hash_length;

	/* Initialize MAC operation */
    TEE_MACInit(*(session_data->hmac_op1_internal), NULL, 0);

    /*
     * Here we could call TEE_MACUpdate but as we will use just one input message
     * it is not needed instead we could use TEE_MACComputeFinal to finalize and
     * accumulate the data.
     */

    /* Define the hash size */
    hash_length = SHA512_HASH_LENGTH;

    /* Finalize the MAC operation with a last chunk of message, and computes the MAC */
    result = TEE_MACComputeFinal(*(session_data->hmac_op1_internal),
    							(uint8_t*)text,
    							(uint32_t)text_length,
    							(uint8_t*)out,
    							&hash_length);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to finalize HMAC-SHA-512 operation: 0x%x", result);
    	#endif
	}

	return result;
}

/**
  * Sets the key for the HMAC-SHA-256 operation.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result set_hmac_sha256_key(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle hmac_key = TEE_HANDLE_NULL;
	TEE_Attribute key_attribute;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> Key of the HMAC-SHA-256 operation
	 * [IN]  params[0].memref.size   -> Size of the key.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate an transient object that will held the key */
	result = TEE_AllocateTransientObject(
					TEE_TYPE_HMAC_SHA256,
					(uint32_t)MAX_HMAC_SHA_256_KEY_SIZE,
					&hmac_key);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate transient key for HMAC-SHA-256 operations: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /*
     * As the key is defined by one attribute parameter it is needed to create an
     * attribute with it
     */
    TEE_InitRefAttribute(
    		&key_attribute,
    		TEE_ATTR_SECRET_VALUE,
    		(uint8_t*)(params[0].memref.buffer),
    		(unsigned int)(params[0].memref.size));

    /* Now use the attribute to set the key into the transient object */
	result = TEE_PopulateTransientObject(hmac_key, &key_attribute, 1);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to populate transient key for HMAC-SHA-256 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Finally, set the operation key */
   	result = TEE_SetOperationKey(*(session_data->hmac_op2), hmac_key);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed set operation key for HMAC-SHA-256 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Resources cleanup */
    cleanup2:
    	/*
    	 * Free the key object as the operation is already set it is no longer
    	 * needed
    	 */
    	TEE_FreeTransientObject(hmac_key);
	cleanup1:
		return result;
}

/**
  * Executes the HMAC-SHA-256 operation.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result hmac_sha256(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint32_t hash_length;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer to write the resulted hash.
	 * [OUT] params[0].memref.size   -> Size of the hash to be written in the buffer.
	 * [IN]  params[1].memref.buffer -> Input buffer with the text to be hashed.
	 * [IN]  params[1].memref.size   -> Size of the input buffer.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL
		|| params[2].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Initialize MAC operation */
    TEE_MACInit(*(session_data->hmac_op2), NULL, 0);

    TEE_MACUpdate(*(session_data->hmac_op2),
    			(uint8_t*)(params[1].memref.buffer),
    			(uint32_t)(params[1].memref.size));

    /* Define the hash size */
    hash_length = (uint32_t)(params[0].memref.size);

    /* Finalize the MAC operation with a last chunk of message, and computes the MAC */
    result = TEE_MACComputeFinal(
    				*(session_data->hmac_op2),
    				(uint8_t*)(params[2].memref.buffer),
    				(uint32_t)(params[2].memref.size),
    				(uint8_t*)(params[0].memref.buffer),
    				&hash_length);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to finalize HMAC-SHA-256 operation: 0x%x", result);
    	#endif
    }

	return result;
}

/**
  * Sets the key for the HMAC-SHA-256 operation. This function is only
  * used by the TA itself.
  * \param session_data A data pointer to a session context.
  * \param key A byte array containing the key to use in the HMAC-SHA256
  *            calculation. The key can be of any length.
  * \param key_length The length, in bytes, of the key.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result set_hmac_sha256_key_internal(Session_data * session_data, const uint8_t *key, const unsigned int key_length)
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle hmac_key = TEE_HANDLE_NULL;
	TEE_Attribute key_attribute;

	/* Allocate an transient object that will held the key */
	result = TEE_AllocateTransientObject(
					TEE_TYPE_HMAC_SHA256,
					MAX_HMAC_SHA_256_KEY_SIZE,
					&hmac_key);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to allocate A transient key for HMAC-SHA-256 operations: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /*
     * As the key is defined by one attribute parameter it is needed to create an
     * attribute with it
     */
    TEE_InitRefAttribute(
    		&key_attribute,
    		TEE_ATTR_SECRET_VALUE,
    		(uint8_t*)key,
    		(unsigned int)key_length);

    /* Now use the attribute the set the key into the transient object */
	result = TEE_PopulateTransientObject(hmac_key, &key_attribute, 1);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to populate the transient key for HMAC-SHA-256 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Finally, set the operation key */
   	result = TEE_SetOperationKey(*(session_data->hmac_op2_internal), hmac_key);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed set operation key for HMAC-SHA-256 operations: 0x%x", result);
    	#endif
    	goto cleanup2;
    }

    /* Resources cleanup */
    cleanup2:
    /*
    	 * Free the key object as the operation is already set it is no longer
    	 * needed
    	 */
    	TEE_FreeTransientObject(hmac_key);
	cleanup1:
		return result;
}

/**
  * Executes the HMAC-SHA-256 operation. This function is only used by the TA
  * itself.
  * \param session_data A data pointer to a session context.
  * \param out A byte array where the HMAC-SHA256 hash value will be written.
  *            This must have space for #SHA256_HASH_LENGTH bytes.
  * \param text1 A byte array containing the first part of the message to use
  *              in the HMAC-SHA256 calculation. The message can be of any
  *              length.
  * \param text1_length The length, in bytes, of the first part of the message.
  * \param text2 A byte array containing the second part of the message to use
  *              in the HMAC-SHA256 calculation. This part will be appended to
  *              the first part of the message. This parameter is optional; it
  *              can be NULL.
  * \param text2_length The length, in bytes, of the second part of the message.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result hmac_sha256_internal(Session_data * session_data, uint8_t *out, const uint8_t *text1, const unsigned int text1_length, const uint8_t *text2, const unsigned int text2_length)
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t hash_length;

	/* Initialize MAC operation */
    TEE_MACInit(*(session_data->hmac_op2_internal), NULL, 0);

    TEE_MACUpdate(*(session_data->hmac_op2_internal), (uint8_t*)text1, (uint32_t)text1_length);

    /* Define the hash size */
    hash_length = SHA256_HASH_LENGTH;

    /* Finalize the MAC operation with a last chunk of message, and computes the MAC */
    result = TEE_MACComputeFinal(*(session_data->hmac_op2_internal),
    							(uint8_t*)text2,
    							(uint32_t)text2_length,
    							(uint8_t*)out,
    							&hash_length);

    if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to finalize HMAC-SHA-256 operation: 0x%x", result);
		#endif
	}

	return result;
}

/*==============================================================================
	HMAC DRBG FUNCTIONS
==============================================================================*/
/**
  * HMAC_DRBG update function. This is a function common to all HMAC_DRBG
  * operations. This function updates the internal state of the DRBG, mixing
  * in some (optional) provided data. This function is only used by the TA
  * itself.
  * \param session_data A data pointer to a session context.
  * \param state The HMAC_DRBG state to update.
  * \param provided_data Optional data to mix into internal state. This may be
  *                      NULL to indicate that there is no provided data.
  *                      Note that there is a difference between "no provided
  *                      data" (specified by passing NULL for this parameter)
  *                      and a zero length string (specified by passing a
  *                      pointer to a zero length byte array for this
  *                      parameter, and passing provided_data_length = 0).
  * \param provided_data_length Length of provided data, in bytes.
  */
static void drbg_update_internal(Session_data * session_data, HMACDRBGState *state, const uint8_t *provided_data, const unsigned int provided_data_length)
{
	uint8_t temp[SHA256_HASH_LENGTH + 1];

	/*
	 * This algorithm is described in pages 45-46 of NIST SP 800-90A.
	 * 1. K = HMAC (K, V || 0x00 || provided_data).
	 */
	TEE_MemMove((uint8_t*)temp,
				(uint8_t*)(state->v),
				(uint32_t)sizeof(state->v));

	temp[SHA256_HASH_LENGTH] = 0x00;

	set_hmac_sha256_key_internal(session_data, state->key, sizeof(state->key));

	hmac_sha256_internal(session_data,
						state->key, temp,
						sizeof(temp),
						provided_data,
						provided_data_length);

	/* 2. V = HMAC (K, V). */
	set_hmac_sha256_key_internal(session_data, state->key, sizeof(state->key));

	hmac_sha256_internal(session_data,
						state->v,
						state->v,
						sizeof(state->v),
						NULL,
						0);

	/* 3. If (provided_data = Null), then return K and V. */
	if (provided_data != NULL)
	{
		/* 4. K = HMAC (K, V || 0x01 || provided_data). */
		TEE_MemMove((uint8_t*)temp,
			(uint8_t*)(state->v),
			(uint32_t)sizeof(state->v));

		temp[SHA256_HASH_LENGTH] = 0x01;

		hmac_sha256_internal(session_data,
							state->key,
							temp,
							sizeof(temp),
							provided_data,
							provided_data_length);

		/* 5. V = HMAC (K, V). */
		set_hmac_sha256_key_internal(session_data,
									state->key,
									sizeof(state->key));

		hmac_sha256_internal(session_data,
							state->v,
							state->v,
							sizeof(state->v),
							NULL,
							0);

		/* 6. Return K and V. */
	}
}

/** Instantiate a HMAC_DRBG state using some seed material.
  * In the terminology of NIST SP 800-90A, the seed material consists of
  * entropy_input, nonce and personalization_string concatenated together.
  * It is the responsibility of the caller to perform this concatenation.
  * This function doesn't do the concatenation because that would require
  * dynamic memory allocation. This function is only used by the TA
  * itself.
  * \param session_data A data pointer to a session context.
  * \param state The HMAC_DRBG state to instantiate.
  * \param seed_material The seed material to seed the HMAC_DRBG state with.
  *                      This may be of arbitrary length and will usually
  *                      consist of several entropy sources concatenated
  *                      together.
  * \param seed_material_length Length of seed material in bytes.
  */
static void drbg_instantiate_internal(Session_data * session_data, HMACDRBGState *state, const uint8_t *seed_material, const unsigned int seed_material_length)
{
	TEE_MemFill((uint8_t*)(state->key), 0x00, (uint32_t)sizeof(state->key));

	TEE_MemFill((uint8_t*)(state->v), 0x01, (uint32_t)sizeof(state->v));

	drbg_update_internal(session_data,
						state,
						seed_material,
						seed_material_length);
}

/** Generate some (deterministic) random bytes from a HMAC_DRBG state. This
  * function is only used by the TA itself.
  * \param session_data A data pointer to a session context.
  * \param out Byte array which will receive the random bytes. This must be
  *            large enough to store requested_bytes bytes.
  * \param state The HMAC_DRBG state to get bytes from. The state must
  *              have been previously instantiated using drbgInstantiate().
  * \param requested_bytes Number of bytes to generate.
  * \param additional_input Optional additional data to mix into HMAC_DRBG
  *                         state. This may be NULL to indicate that there is
  *                         no additional input.
  * \param additional_input_length Length of additional input, in number of
  *                                bytes.
  */
static void drbg_generate_internal(Session_data * session_data, uint8_t *out, HMACDRBGState *state, const unsigned int requested_bytes, const uint8_t *additional_input, const unsigned int additional_input_length)
{
	unsigned int bytes;
	unsigned int copy_size;

	if (additional_input != NULL)
		drbg_update_internal(session_data,
							state,
							additional_input,
							additional_input_length);

	bytes = 0;

	while (bytes < requested_bytes)
	{
		/* V = HMAC (Key, V). */
		hmac_sha256_internal(session_data,
							state->v,
							state->v,
							sizeof(state->v),
							NULL,
							0);

		copy_size = MIN(requested_bytes - bytes, sizeof(state->v));

		TEE_MemMove((uint8_t*)&(out[bytes]),
					(uint8_t*)(state->v),
					(uint32_t)copy_size);

		bytes += copy_size;
	}

	drbg_update_internal(session_data,
						state,
						additional_input,
						additional_input_length);
}

/*==============================================================================
	WALLET STORAGE OPERATIONS
==============================================================================*/
/**
  * Creates the wallet storage by using the data stream from a persistent
  * object. It also truncates the data stream to #NV_MEMORY_SIZE.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result create_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE;

    /*
	 * Expected:
	 * [IN] params[0].memref.buffer-> Name of the wallet storage id.
	 * [IN] params[0].memref.size  -> Size of the name of the wallet storage id.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * Confirm the type of the receive parameters as well if the storageID
	 * sent is not NULL
	 */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the storage was already open or created */
	if (session_data->is_storage_open == true
		|| session_data->is_storage_created == true)
		return TEE_ERROR_BAD_STATE;

	/* Set the wallet handle to null */
	*(session_data->wallet_handle) = TEE_HANDLE_NULL;

	/*
	 * Create the persistent object that will be used as the wallet storage.
	 */
	result = TEE_CreatePersistentObject(
				TEE_STORAGE_PRIVATE,
				params[0].memref.buffer,
				params[0].memref.size,
				flags,
				NULL,
				NULL,
				0,
				session_data->wallet_handle);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to create a persistent object for wallet storage: 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Copy the storageID to the session data structure */
	TEE_MemMove((char*)(session_data->storageID),
				(char*)(params[0].memref.buffer),
				params[0].memref.size);

	session_data->storageIDLen = params[0].memref.size;

	/*
	 * When writing to a position beyond the stream's end, the date stream is
	 * first extended with bytes (zeros) until the length indicated by the data
	 * position indicator is reached, and then 'size' bytes are written to the
	 * stream.
	 * When reading past the end-of-stream, the function TEE_ReadObjectData
	 * stops reading data at the end-of-stream and returns the data read up to
	 * that point. If the position is at, or past, the end of the data when read
	 * function is called, then no bytes are read.
	 * So, because of the situations described above there is a necessity to
	 * increase the size of the data stream to the #NV_MEMORY_SIZE. This way
	 * is avoided wrong readings and a constant increase of size of the data
	 * stream.
	 */
	result = TEE_TruncateObjectData(*(session_data->wallet_handle),
									NV_MEMORY_SIZE);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to extend the wallet storage: 0x%x", result);
		#endif
		goto cleanup2;
	}

	session_data->is_storage_created = true;

	/* Resources cleanup */
	cleanup2:
		TEE_CloseObject(*(session_data->wallet_handle));
		/*
		 * As the objective of this function is to only create the storage the
		 * handle is set to NULL
		 */
		*(session_data->wallet_handle) = TEE_HANDLE_NULL;
	cleanup1:
		return result;
}

/**
  * Opens the wallet storage.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result open_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;

	/* Set the flags which the wallet will be opened with */
    uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META
    					| TEE_DATA_FLAG_ACCESS_READ
    					| TEE_DATA_FLAG_ACCESS_WRITE;

    /* It is not expected any parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	/* Confirm the types of parameters received */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the storage was already open or created */
	if (session_data->is_storage_open == true
		|| session_data->is_storage_created == false)
		return TEE_ERROR_BAD_STATE;

	/* Unused parameters */
	(void)&params;

	*(session_data->wallet_handle) = TEE_HANDLE_NULL;

	/* Open the wallet storage that is a data stream of an persistent object */
	result = TEE_OpenPersistentObject(
					TEE_STORAGE_PRIVATE,
					(char*)(session_data->storageID),
					session_data->storageIDLen,
					flags,
					session_data->wallet_handle);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to open the wallet storage: 0x%x", result);
		#endif
		goto cleanup1;
	}

	session_data->is_storage_open = true;

	/* Cleanup resources */
	cleanup1:
		return result;
}

/**
  * Closes the wallet storage meaning that closes the persistent object that
  * contains the data stream with the wallet storage.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result close_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	/* It is not expected any parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	/* Check the type of the parameters received */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the storage was already open or created */
	if (session_data->is_storage_open == false
		|| session_data->is_storage_created == false)
		return TEE_ERROR_BAD_STATE;

	/* Unused parameters */
	(void)&params;

	/* Close the wallet storage */
	TEE_CloseObject(*(session_data->wallet_handle));

	*(session_data->wallet_handle) = TEE_HANDLE_NULL;

	session_data->is_storage_open = false;

	return TEE_SUCCESS;
}

/**
  * Deletes the wallet storage.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result delete_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;

	/* It is not expected any parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	/* Checks the types of the parameters received */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the storage was already created */
	if (session_data->is_storage_created == false)
		return TEE_ERROR_BAD_STATE;

	/* Unused parameters */
	(void)&params;

	/*
	 * If the storage is not opened, it opens it because the function to delete
	 * needs the storage opened
	 */
	if (session_data->is_storage_open == false)
	{
		result = open_wallet_storage(session_data, param_types, params);

		if (result != TEE_SUCCESS)
		{
			#ifdef OP_TEE_TA
			DMSG("Failed to open the wallet storage: 0x%x", result);
			#endif
			goto cleanup1;
		}
	}

	/* Close and delete the wallet storage */
	result = TEE_CloseAndDeletePersistentObject1(*(session_data->wallet_handle));

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to closing and deleting the wallet storage: 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Set the session data to default values*/
	*(session_data->wallet_handle) = TEE_HANDLE_NULL;
	session_data->is_storage_open = false;
	session_data->is_storage_created = false;

	/* Resources cleanup */
	cleanup1:
		return result;
}

/**
  * Seeks a the position on the data stream of the wallet storage.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result seek_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [IN)  params[0].value.a -> Address to seek the wallet storage.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the storage was already open or created */
	if (session_data->is_storage_open == false
		|| session_data->is_storage_created == false)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Set the position of the data stream to the address indicated at
	 * params[0].value.a (SET the address as a offset from the beginning of the
	 * data stream).
	 */
    result = TEE_SeekObjectData(
    				*(session_data->wallet_handle),
    				(int32_t)(params[0].value.a),
    				TEE_DATA_SEEK_SET);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to seek while writing: 0x%x", result);
    	#endif
    }

	return result;
}

/**
  * Writes one byte in the wallet storage at the position that the data stream
  * is currently at.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result write1_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> Data to write into the storage.
	 * [IN]  params[0].memref.size   -> Size of the data to write into the
	 *									storage.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * When the parameters received are different from the ones expected or
	 * when the pointer to the data to be written (params[0].memref.buffer) is
	 * NULL return TEE_ERROR_BAD_PARAMETERS.
	 */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the storage is open */
	if (session_data->is_storage_open == false)
		return TEE_ERROR_BAD_STATE;

    /*
     * Write the data in the data stream. The data to be written is pointed by
     * params[0].memref.buffer.
     */
    result = TEE_WriteObjectData(
    				*(session_data->wallet_handle),
    				(uint8_t*)(params[0].memref.buffer),
    				(size_t)(params[0].memref.size));

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to write in the wallet storage: 0x%x", result);
    	#endif
    }

	return result;
}

/**
  * Reads one byte from the wallet storage at the position that data stream is
  * currently at.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result read1_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	size_t count = 0;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer to write the data read.
	 * [OUT] params[0].memref.size   -> Size of the data to be read.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * When the parameters received are different from the ones expected or
	 * when the pointer to buffer were the data read will be written
	 * (params[0].memref.buffer) is NULL return TEE_ERROR_BAD_PARAMETERS.
	 */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the storage is open */
	if (session_data->is_storage_open == false)
		return TEE_ERROR_BAD_STATE;

	/*
     * Write the data read in params[0].memref.buffer.
     */
    result = TEE_ReadObjectData(
    				*(session_data->wallet_handle),
    				(uint8_t*)(params[0].memref.buffer),
    				(size_t)(params[0].memref.size),
    				&count);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to read from the wallet storage: 0x%x", result);
    	#endif
    }

	return result;
}

/**
  * Writes in the wallet storage meaning that writes in the data stream of the
  * persistent object that is considerate the wallet storage. This function is
  * only used by the TA itself.
  * \param session_data A data pointer to a session context.
  * \param inputBuffer A pointer to the buffer that contains the data to be
  *                    written.
  * \param length The amount of bytes to write in the wallet storage.
  * \param address Byte offset specifying where in the partition to
  *                start writing to.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result write_wallet_storage_internal(Session_data * session_data, uint8_t * inputBuffer, size_t length, int32_t address)
{
	TEE_Result result = TEE_SUCCESS;

	/* Do some sanity checks */
	if (inputBuffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (session_data->is_storage_open == false)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Set the position of the data stream to the address indicated at
	 * the address (SET the address as a offset from the beginning of the
	 * data stream).
	 */
    result = TEE_SeekObjectData(*(session_data->wallet_handle),
			    				(int32_t)address,
			    				TEE_DATA_SEEK_SET);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to seek while writing: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /*
     * Write the data in the data stream. The data to be written is pointed by
     * inputBuffer.
     */
    result = TEE_WriteObjectData(*(session_data->wallet_handle),
			    				(uint8_t*)inputBuffer,
			    				(size_t)length);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to write in the wallet storage: 0x%x", result);
    	#endif
    }

   	/* Resource cleanup */
    cleanup1:
		return result;
}

/**
  * Reads from the wallet storage meaning that reads from the data stream of the
  * persistent object that is considerate the wallet storage. This function is
  * only used by the TA itself.
  * \param session_data A data pointer to a session context.
  * \param outputBuffer A pointer to the buffer were the read data will be
  *                    written to.
  * \param length The amount of bytes to read from the wallet storage.
  * \param address Byte offset specifying where in the partition to
  *                start reading from.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result read_wallet_storage_internal(Session_data * session_data, uint8_t * outputBuffer, uint32_t length, int32_t address)
{
	TEE_Result result = TEE_SUCCESS;
	size_t count = 0;

	/* Do some sanity checks */
	if (outputBuffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the wallet storage is open */
	if (session_data->is_storage_open == false)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Set the position of the data stream to the address indicated at
	 * address (SET the address as a offset from the beginning of the
	 * data stream).
	 */
    result = TEE_SeekObjectData(*(session_data->wallet_handle),
				    			(int32_t)address,
				    			TEE_DATA_SEEK_SET);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to seek while reading: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

    /*
     * Write the data read in the outputBuffer.
     */
    result = TEE_ReadObjectData(*(session_data->wallet_handle),
			    				(uint8_t*)outputBuffer,
			    				(size_t)length,
			    				&count);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to read from the wallet storage: 0x%x", result);
    	#endif
    }

    /* Resource cleanup */
    cleanup1:
		return result;
}

/**
  * Flushes the buffered data into the wallet storage.
  * \param session_data A data pointer to a session context.
  * \param nv_error NonVolatile error.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result flush_wallet_storage_internal(Session_data * session_data, NonVolatileReturn * nv_error)
{
	TEE_Result result = TEE_SUCCESS;
	*nv_error = NV_NO_ERROR;

	/* Check if the storage was already created and opened */
	if (session_data->is_storage_created == false
		|| session_data->is_storage_open == false)
	{
		result = TEE_ERROR_BAD_STATE;
		*nv_error = NV_IO_ERROR;
		goto cleanup1;
	}

	/* If the data in the write cache is valid */
	if (session_data->write_cache_valid)
	{
		/* Sanity check */
		if ((session_data->write_cache_tag) >= NV_MEMORY_SIZE)
		{
			result = TEE_ERROR_BAD_STATE;
			*nv_error = NV_INVALID_ADDRESS;
			goto cleanup1;
		}

		/* Write the write-cache into the wallet storage */
		result = write_wallet_storage_internal(
						session_data,
						(uint8_t*)(session_data->write_cache),
						(size_t)SECTOR_SIZE,
						session_data->write_cache_tag);

		if (result != TEE_SUCCESS)
		{
			#ifdef OP_TEE_TA
	    	DMSG("Failed to write in the wallet storage: 0x%x", result);
	    	#endif
	    	*nv_error = NV_IO_ERROR;
	    	goto cleanup1;
	    }

	    /* Invalid the write cache */
		session_data->write_cache_valid = false;
		session_data->write_cache_tag = 0;

		/* Reset the content to zeros */
		TEE_MemFill(session_data->write_cache, 0, (uint32_t)SECTOR_SIZE);
	}

	/* Resources cleanup */
	cleanup1:
		return result;
}

/**
  * Wrapper of flush_wallet_storage_internal() for a CA command.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result flush_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	NonVolatileReturn nv_error = NV_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].value.a -> NonVolatileReturn error.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Checks the types of the parameters received */
	if (param_types != exp_param_types)
	{
		result = TEE_ERROR_BAD_PARAMETERS;
		nv_error = NV_IO_ERROR;
		goto cleanup1;
	}

	result = flush_wallet_storage_internal(session_data, &nv_error);

	/* Resources cleanup */
	cleanup1:
		params[0].value.a = (uint32_t)nv_error;
		return result;
}

/**
  * Writes in the write cache and when needed flushes the data into the wallet
  * storage.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result write_cache_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	NonVolatileReturn nv_error = NV_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t address_tag;
	uint32_t address;
	uint32_t length;
    uint32_t end;
    uint32_t data_index;
    uint32_t exp_param_types;

    /*
	 * Expected:
	 * [IN]  params[0].memref.buffer-> Data to write in the storage.
	 * [IN]  params[0].memref.size  -> Size of the data to write in the storage.
	 * [IN]  params[1].value.a 	    -> Address where the data will be written to.
	 * [OUT] params[1].value.b 	    -> NonVolatileReturn error;
	 */
	exp_param_types =  TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
	{
		result = TEE_ERROR_BAD_PARAMETERS;
		nv_error = NV_IO_ERROR;
		goto cleanup1;
	}

	/* Check if the wallet storage is open */
	if (session_data->is_storage_open == false)
	{
		result = TEE_ERROR_BAD_STATE;
		nv_error = NV_IO_ERROR;
		goto cleanup1;
	}

    address = params[1].value.a;
    length = params[0].memref.size;

    /* Set the end of the region to write */
    end = address + length;

    /* Initialize data index variable */
    data_index = 0;

    /* Process till the end of the data to be written */
    while (address < end)
    {
    	/* Setting the address of the sector to be written */
    	address_tag = address & SECTOR_TAG_MASK;

    	/*
         * If it write_cache is not valid or the address of the write_cache is
         * different from the address of the sector to be written
         */
    	if (!(session_data->write_cache_valid)
    		|| (address_tag != (session_data->write_cache_tag)))
    	{
    		/* Address is not in cache; load sector into memory */
    		if (session_data->write_cache_valid)
    		{
    			/* Flush the cache to secure storage */
    			result = flush_wallet_storage_internal(session_data, &nv_error);

    			if (result != TEE_SUCCESS || nv_error != NV_NO_ERROR)
			    {
			    	#ifdef OP_TEE_TA
			    	DMSG("Failed to flush into the wallet storage: 0x%x", result);
			    	#endif
			    	goto cleanup1;
			    }
    		}

    		/* Set up the new values for the write cache */
    		session_data->write_cache_valid = true;
    		session_data->write_cache_tag = address_tag;

    		/* Read the sector to be written from the secure storage */
    		result = read_wallet_storage_internal(
    						session_data,
    						(uint8_t*)(session_data->write_cache),
    						(size_t)SECTOR_SIZE,
    						address_tag);

    		if (result != TEE_SUCCESS)
		    {
		    	#ifdef OP_TEE_TA
		    	DMSG("Failed to read from the wallet storage: 0x%x", result);
		    	#endif
		    	goto cleanup1;
		    }
    	}

    	/* Address is guaranteed to be in cache; write to the cache. */
    	(session_data->write_cache)[address & SECTOR_OFFSET_MASK] = ((uint8_t*)(params[0].memref.buffer))[data_index];

    	address++;
    	data_index++;
    }/* End while (address < end) */

   	/* Resource cleanup */
    cleanup1:
    	params[1].value.b = (uint32_t)nv_error;
		return result;
}

/**
  * Reads from the write cache or from the wallet storage when needed.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result read_cache_wallet_storage(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t address_tag;
	uint32_t address;
	uint32_t length;
    uint32_t end;
    uint32_t nv_read_length;
    uint32_t data_index;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer to write the data read.
	 * [OUT] params[0].memref.size   -> Size of the data to be read.
	 * [IN]  params[1].value.a 	     -> Start address to read the data from.
	 * [OUT] params[1].value.b 	     -> Size of the data that was actually read.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the wallet storage is open */
	if (session_data->is_storage_open == false)
		return TEE_ERROR_BAD_STATE;

	/* Set the end of the region to read */
	address = params[1].value.a;
	length = params[0].memref.size;
	end = address + length;

	/* Length of contiguous non-volatile read */
	nv_read_length = 0;

	/* Initialize data index variable */
	data_index = 0;

	/*
     * The code below attempts to group non-volatile reads together. It is
     * possible (and simpler) to read one byte at a time, but that is much less
     * efficient. Since reads are expected to occur much more frequently than
     * writes, inefficient reading will incur a significant performance penalty.
     */
	while (address < end)
	{
		/* Set the address of the sector where the the data is to be read from */
		address_tag = address & SECTOR_TAG_MASK;

		/* The data in the cache is from the sector to be read */
		if ((session_data->write_cache_valid) && (address_tag == (session_data->write_cache_tag)))
		{
			if (nv_read_length > 0)
			{
				/*
                 * Beginning of write cache; end of contiguous non-volatile
                 * read.
                 */
				result = read_wallet_storage_internal(
							session_data,
							(uint8_t*)&((uint8_t*)(params[0].memref.buffer))[data_index],
							(size_t)nv_read_length,
							address - nv_read_length);

				if (result != TEE_SUCCESS)
			    {
			    	#ifdef OP_TEE_TA
			    	DMSG("Failed to read from the wallet storage: 0x%x", result);
			    	#endif
			    	goto cleanup1;
			    }

			    data_index += nv_read_length;
                nv_read_length = 0;
			}

			/* Address is in cache; read from the cache. */
			((uint8_t*)(params[0].memref.buffer))[data_index] = (session_data->write_cache)[address & SECTOR_OFFSET_MASK];

			data_index++;
		}
		else
		{
			/* Don't read just yet; queue it up and do all the reads together. */
			nv_read_length++;
		}

		address++;
	} /* End while (address < end) */

	if (nv_read_length > 0)
	{
		/* End of contiguous non-volatile read. */
		result = read_wallet_storage_internal(
					session_data,
					(uint8_t*)&((uint8_t*)(params[0].memref.buffer))[data_index],
					(size_t)nv_read_length,
					address - nv_read_length);

		if (result != TEE_SUCCESS)
	    {
	    	#ifdef OP_TEE_TA
	    	DMSG("Failed to read from the wallet storage: 0x%x", result);
	    	#endif
	    	goto cleanup1;
	    }
	}

    /* Resource cleanup */
    cleanup1:
		return result;
}

/** Wrapper around write_cache_wallet_storage() which also encrypts data
  * using aes_xts_internal(). Because this uses encryption, it is much slower
  * than write_cache_wallet_storage(). The parameters and return values are
  * identical to that of write_cache_wallet_storage(). It is to be
  * used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param data A pointer to the data to be written.
  * \param length The number of bytes to write.
  * \param address Byte offset specifying where in the partition to
  *                start writing to.
  * \param nv_error NonVolatilereturn error.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result encrypted_write_wallet_storage_internal(Session_data * session_data, uint8_t *data, uint32_t length, uint32_t address, NonVolatileReturn * nv_error)
{
	TEE_Result result = TEE_SUCCESS;
	uint8_t ciphertext[length];
	uint8_t plaintext[length];

	/* Declare parameters that will be used in read operations */
	TEE_Param read_params[4];
	uint32_t read_param_types;

	/* Declare parameters that will be used in write operations */
	TEE_Param write_params[4];
	uint32_t write_param_types;

	/*
	 * Read parameters:
	 * [OUT] params[0].memref.buffer -> Buffer to store the read data.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [IN]  params[1].value.a       -> Starting address of the reading.
	 * [OUT] params[1].value.b       -> Size actually read.
	 */
	read_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_MEMREF_OUTPUT,
									TEE_PARAM_TYPE_VALUE_INOUT,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	/*
	 * Write parameters:
	 * [IN]  params[0].memref.buffer -> Buffer with data to write in the storage.
	 * [IN]  params[0].memref.size   -> Size of the buffer to be wrote.
	 * [IN]  params[1].value.a       -> Starting address of the writing.
	 * [OUT] params[1].value.b       -> NonVolatileReturn error.
	 */
	write_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_MEMREF_INPUT,
									TEE_PARAM_TYPE_VALUE_INOUT,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	*nv_error = NV_IO_ERROR;

	if ((address + length) < address)
	{
		/*
		 * Here the return should be return TEE_ERROR_BAD_PARAMETERS;
		 * but as this will be treated as an error by the CA the most safest way
		 * is to set as TEE_ERROR_BAD_STATE so signal an operation that failed
		 * but without the needing to exit the program
		 */
		return TEE_ERROR_BAD_STATE;
	}


	/* Define the read operation parameters */
	read_params[0].memref.buffer = (uint8_t *)ciphertext;
	read_params[0].memref.size = length;
	read_params[1].value.a = address;

	/* Fetch the data that is currently in the position to be write */
	result = read_cache_wallet_storage(session_data,
										read_param_types,
										read_params);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Read wallet storage failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Decrypt the data fetched */
	result = aes_xts_internal(session_data,
							TEE_MODE_DECRYPT,
							ciphertext,
							length,
							plaintext,
							length);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("AES XTS Decrypt failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Replace the data decrypted with the new data to be written */
	TEE_MemMove((uint8_t*)plaintext, (uint8_t*)data, length);

	/* Encrypt the data to be written */
	result = aes_xts_internal(session_data,
							TEE_MODE_ENCRYPT,
							plaintext,
							length,
							ciphertext,
							length);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("AES XTS Encrypt failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Define the write operation parameters */
	write_params[0].memref.buffer = (uint8_t *)ciphertext;
	write_params[0].memref.size = length;
	write_params[1].value.a = address;

	/* Write the data */
	result = write_cache_wallet_storage(session_data,
										write_param_types,
										write_params);

	*nv_error = (NonVolatileReturn)(write_params[1].value.b);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Write wallet storage failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	cleanup1:
		return result;
}

/** Wrapper around read_cache_wallet_storage() which also decrypts data
  * using aes_xts_internal(). Because this uses encryption, it is much slower
  * than read_cache_wallet_storage(). The parameters and return values are
  * identical to that of read_cache_wallet_storage(). It is to be
  * used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param data A pointer to the buffer which will receive the data.
  * \param length The number of bytes to read.
  * \param address Byte offset specifying where in the partition to
  *                start reading from.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result encrypted_read_wallet_storage_internal(Session_data * session_data, uint8_t *data, uint32_t length, uint32_t address)
{
	TEE_Result result = TEE_SUCCESS;
	uint8_t ciphertext[length];
	uint8_t plaintext[length];

	/* Declare the read operation parameters */
	TEE_Param read_params[4];
	uint32_t read_param_types;

	/*
	 * Read parameters:
	 * [OUT] params[0].memref.buffer -> Buffer to store the read data.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [IN]  params[1].value.a       -> Starting address of the reading.
	 * [OUT] params[1].value.b       -> Size actually read.
	 */
	read_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Check if the address overflows */
	if ((address + length) < address)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Define the read operation parameters */
	read_params[0].memref.buffer = (uint8_t *)ciphertext;
	read_params[0].memref.size = length;
	read_params[1].value.a = address;

	/* Read the data from the storage */
	result = read_cache_wallet_storage(session_data,
									read_param_types,
									read_params);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Read wallet storage failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Decrypt the data read */
	result = aes_xts_internal(session_data,
							TEE_MODE_DECRYPT,
							ciphertext,
							length,
							plaintext,
							length);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("AES XTS Decrypt failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Copy the plain text to the output buffer */
	TEE_MemMove((uint8_t*)data, (uint8_t*)plaintext, length);

	cleanup1:
		return result;
}

/*==============================================================================
	ENDIAN FUNCTIONS
==============================================================================*/
/**
  *  Write 32 bit unsigned integer into a byte array in big-endian format. It is
  * to be used internally (only by the functions of the TA itself).
  * \param out The destination byte array. This must have space for at
  *            least 4 bytes.
  * \param in The source integer.
  */
static void write_u32_big_endian_internal(uint8_t *out, uint32_t in)
{
	out[0] = (uint8_t)(in >> 24);
	out[1] = (uint8_t)(in >> 16);
	out[2] = (uint8_t)(in >> 8);
	out[3] = (uint8_t)in;
}

/**
  * Write 32 bit unsigned integer into a byte array in little-endian format. It
  * is to be used internally (only by the functions of the TA itself).
  * \param out The destination byte array. This must have space for at
  *            least 4 bytes.
  * \param in The source integer.
  */
static void write_u32_little_endian_internal(uint8_t * out, uint32_t in)
{
	out[0] = (uint8_t)in;
	out[1] = (uint8_t)(in >> 8);
	out[2] = (uint8_t)(in >> 16);
	out[3] = (uint8_t)(in >> 24);
}

/**
  * Write the hash value into a byte array, respecting endianness. It is
  * to be used internally (only by the functions of the TA itself).
  * \param out The byte array which will receive the hash. This byte array
  *            must have space for at least 32 bytes, even if the hash
  *            function's result is smaller than 256 bits.
  * \param hs The hash state to read the hash value from.
  * \param do_write_big_endian Whether the hash should be written in a
  *                            big-endian way (useful for computing the first
  *                            hash of a double SHA-256 hash) instead of a
  *                            little-endian way (useful for sending off to a
  *                            signing function).
  * \warning The appropriate hash-specific finish function must be called before
  *			 this function.
  */
static void write_hash_to_byte_array_internal(uint8_t * out, uint32_t * hash, bool do_write_big_endian)
{
	uint8_t i;

	if (do_write_big_endian)
	{
		for (i = 0; i < 8; i++)
			write_u32_big_endian_internal(&(out[i * 4]), hash[i]);
	}
	else
	{
		for (i = 0; i < 8; i++)
			write_u32_little_endian_internal(&(out[i * 4]), hash[7 - i]);
	}
}

/**
  * Swap endianness of a 32 bit unsigned integer.
  * \param v The integer to modify.
  */
static void swap_endian_internal(uint32_t *v)
{
	uint8_t t;
	uint8_t *r;

	r = (uint8_t *)v;
	t = r[0];
	r[0] = r[3];
	r[3] = t;
	t = r[1];
	r[1] = r[2];
	r[2] = t;
}

/*==============================================================================
	BIGNUM 256 FUNCTIONS

	GlobalPlatform had an TEE Arithmetical API that could be used here but that
	would lead to a lot of changes in the original code so it was opted the
	option to use that API was discarded.
==============================================================================*/
/**
  * Compare two multi-precision numbers of arbitrary size.It is
  * to be used internally (only by the functions of the TA itself).
  * \param op1 One of the numbers to compare.
  * \param op2 The other number to compare. This may alias op1.
  * \param size The size of the multi-precision numbers op1 and op2, in number
  *             of bytes.
  * \return #BIGCMP_GREATER if op1 > op2, #BIGCMP_EQUAL if they're equal
  *         and #BIGCMP_LESS if op1 < op2.
  */
static uint8_t big_compare_variable_size_internal(uint8_t *op1, uint8_t *op2, uint8_t size)
{
	uint8_t i;
	uint8_t r;
	uint8_t cmp;

	r = BIGCMP_EQUAL;

	for (i = (uint8_t)(size - 1); i < size; i--)
	{
		/*
		 * The following code is a branch free way of doing:
		 * if (r == BIGCMP_EQUAL)
		 * {
		 *     if (op1[i] > op2[i])
		 *     {
		 *         r = BIGCMP_GREATER;
		 *     }
		 * }
		 * if (r == BIGCMP_EQUAL)
		 * {
		 *     if (op2[i] > op1[i])
		 *     {
		 *         r = BIGCMP_LESS;
		 *     }
		 * }
		 * Note that it relies on BIGCMP_EQUAL having the value 0.
		 * It inspired by the code at:
		 * http://aggregate.ee.engr.uky.edu/MAGIC/#Integer%20Selection
		 */
		cmp = (uint8_t)((((uint16_t)((int)op2[i] - (int)op1[i])) >> 8) & BIGCMP_GREATER);
		r = (uint8_t)(((((uint16_t)(-(int)r)) >> 8) & (r ^ cmp)) ^ cmp);
		cmp = (uint8_t)((((uint16_t)((int)op1[i] - (int)op2[i])) >> 8) & BIGCMP_LESS);
		r = (uint8_t)(((((uint16_t)(-(int)r)) >> 8) & (r ^ cmp)) ^ cmp);
	}

	return r;
}

/**
  * Compare two 32 byte multi-precision numbers. It is
  * to be used internally (only by the functions of the TA itself).
  * \param op1 One of the 32 byte numbers to compare.
  * \param op2 The other 32 byte number to compare. This may alias op1.
  * \return #BIGCMP_GREATER if op1 > op2, #BIGCMP_EQUAL if they're equal
  *         and #BIGCMP_LESS if op1 < op2.
  */
static uint8_t big_compare_internal(BigNum256 op1, BigNum256 op2)
{
	return big_compare_variable_size_internal(op1, op2, 32);
}

/**
  * Check if a multi-precision number of arbitrary size is equal to zero.
  * \param op1 The number to check. It is
  * to be used internally (only by the functions of the TA itself).
  * \param size The size of the multi-precision number op1, in number of
  *             bytes.
  * \return 1 if op1 is zero, 0 if op1 is not zero.
  */
static uint8_t big_is_zero_variable_size_internal(uint8_t *op1, uint8_t size)
{
	uint8_t i;
	uint8_t r;

	r = 0;

	for (i = 0; i < size; i++)
		r |= op1[i];

	/* The following line does: "return r ? 0 : 1;". */
	return (uint8_t)((((uint16_t)(-(int)r)) >> 8) + 1);
}

/**
  * Check if a 32 byte multi-precision number is equal to zero. It is
  * to be used internally (only by the functions of the TA itself).
  * \param op1 The 32 byte number to check.
  * \return 1 if op1 is zero, 0 if op1 is not zero.
  */
static uint8_t big_is_zero_internal(BigNum256 op1)
{
	return big_is_zero_variable_size_internal(op1, 32);
}

/**
  * Set a 32 byte multi-precision number to zero. It is
  * to be used internally (only by the functions of the TA itself).
  * \param r The 32 byte number to set to zero.
  */
static void big_set_zero_internal(BigNum256 r)
{
	TEE_MemFill((BigNum256)r, (uint32_t)0, (uint32_t)32);
}

/**
  * Assign one 32 byte multi-precision number to another. It is
  * to be used internally (only by the functions of the TA itself).
  * \param r The 32 byte number to assign to.
  * \param op1 The 32 byte number to read from.
  */
static void big_assign_internal(BigNum256 r, BigNum256 op1)
{
	TEE_MemMove((BigNum256)r, (BigNum256)op1, (uint32_t)32);
}

/**
  * Swap endian representation of a 256 bit integer. It is to be used
  * internally (only by the functions of the TA itself).
  * \param buffer An array of 32 bytes representing the integer to change.
  */
static void swap_endian256_internal(BigNum256 buffer)
{
	uint8_t i;
	uint8_t temp;

	for (i = 0; i < 16; i++)
	{
		temp = buffer[i];
		buffer[i] = buffer[31 - i];
		buffer[31 - i] = temp;
	}
}

/**
  * Set prime finite field parameters. The arrays passed as parameters to
  * this function will never be written to, hence the const modifiers. It is to
  * be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param in_n See #n.
  * \param in_complement_n See #complement_n.
  * \param in_size_complement_n See #size_complement_n.
  * \warning There are some restrictions on what the parameters can be.
  *          See #n, #complement_n and #size_complement_n for more details.
  */
static void big_set_field_internal(Session_data * session_data, const uint8_t *in_n, const uint8_t *in_complement_n, const uint8_t in_size_complement_n)
{
	session_data->n = (BigNum256)in_n;
	session_data->complement_n = (uint8_t *)in_complement_n;
	session_data->size_complement_n = (uint8_t)in_size_complement_n;
}

/**
  * Add (r = op1 + op2) two multi-precision numbers of arbitrary size,
  * ignoring the current prime finite field. In other words, this does
  * multi-precision binary addition. It is to be used
  * internally (only by the functions of the TA itself).
  * \param r The result will be written into here.
  * \param op1 The first operand to add. This may alias r.
  * \param op2 The second operand to add. This may alias r or op1.
  * \param op_size Size, in bytes, of the operands and the result.
  * \return 1 if carry occurred, 0 if no carry occurred.
  */
static uint8_t big_add_variable_size_no_modulo_internal(uint8_t *r, uint8_t *op1, uint8_t *op2, uint8_t op_size)
{
	uint16_t partial;
	uint8_t carry;
	uint8_t i;

	carry = 0;

	for (i = 0; i < op_size; i++)
	{
		partial = (uint16_t)((uint16_t)op1[i] + (uint16_t)op2[i] + (uint16_t)carry);
		r[i] = (uint8_t)partial;
		carry = (uint8_t)(partial >> 8);
	}

	return carry;
}

/**
  * Subtract (r = op1 - op2) two multi-precision numbers of arbitrary size,
  * ignoring the current prime finite field. In other words, this does
  * multi-precision binary subtraction. It is to be used
  * internally (only by the functions of the TA itself).
  * \param r The result will be written into here.
  * \param op1 The operand to subtract from. This may alias r.
  * \param op2 The operand to subtract off op1. This may alias r or op1.
  * \param op_size Size, in bytes, of the operands and the result.
  * \return 1 if borrow occurred, 0 if no borrow occurred.
  */
static uint8_t big_subtract_variable_size_no_modulo_internal(uint8_t *r, uint8_t *op1, uint8_t *op2, uint8_t op_size)
{
	uint16_t partial;
	uint8_t borrow;
	uint8_t i;

	borrow = 0;

	for (i = 0; i < op_size; i++)
	{
		partial = (uint16_t)((uint16_t)op1[i] - (uint16_t)op2[i] - (uint16_t)borrow);
		r[i] = (uint8_t)partial;
		borrow = (uint8_t)((uint8_t)(partial >> 8) & 1);
	}

	return borrow;
}

/**
  * Ignoring the current prime finite field. In other words, this does
  * multi-precision binary subtraction. It is to be used
  * internally (only by the functions of the TA itself).
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to subtract from. This may alias r.
  * \param op2 The 32 byte operand to subtract off op1. This may alias r or op1.
  * \return 1 if borrow occurred, 0 if no borrow occurred.
  */
static uint8_t big_subtract_no_modulo_internal(BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	return big_subtract_variable_size_no_modulo_internal(r, op1, op2, 32);
}

/**
  * Compute op1 modulo #n, where op1 is a 32 byte multi-precision number.
  * The "modulo" part makes it sound like this function does division
  * somewhere, but since #n is also a 32 byte multi-precision number, all
  * this function actually does is subtract #n off op1 if op1 is >= #n. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to apply the modulo to. This may alias r.
  */
static void big_modulo_internal(Session_data * session_data, BigNum256 r, BigNum256 op1)
{
	uint8_t cmp;
	uint8_t *lookup[2];
	uint8_t zero[32];

	big_set_zero_internal(zero);

	/*
	 * The following 2 lines do:
	 * cmp = "bigCompare(op1, n) == BIGCMP_LESS ? 1 : 0".
	 */
	cmp = (uint8_t)(big_compare_internal(op1, session_data->n) ^ BIGCMP_LESS);
	cmp = (uint8_t)((((uint16_t)(-(int)cmp)) >> 8) + 1);

	lookup[0] = session_data->n;
	lookup[1] = zero;

	big_subtract_no_modulo_internal(r, op1, lookup[cmp]);
}

/**
  * Add (r = (op1 + op2) modulo #n) two 32 byte multi-precision numbers under
  * the current prime finite field. It is to be used
  * internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param r The 32 byte result will be written into here.
  * \param op1 The first 32 byte operand to add. This may alias r.
  * \param op2 The second 32 byte operand to add. This may alias r or op1.
  * \warning op1 and op2 must both be < #n.
  */
static void big_add_internal(Session_data * session_data, BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	uint8_t too_big;
	uint8_t cmp;
	uint8_t *lookup[2];
	uint8_t zero[32];

	big_set_zero_internal(zero);

	/*
	assert(big_compare_internal(op1, n) == BIGCMP_LESS);
	assert(big_compare_internal(op2, n) == BIGCMP_LESS);
	*/

	too_big = big_add_variable_size_no_modulo_internal(r, op1, op2, 32);

	cmp = (uint8_t)(big_compare_internal(r, session_data->n) ^ BIGCMP_LESS);
	cmp = (uint8_t)((((uint16_t)(-(int)cmp)) >> 8) & 1);

	too_big |= cmp;

	lookup[0] = zero;
	lookup[1] = session_data->n;

	big_subtract_no_modulo_internal(r, r, lookup[too_big]);
}

/**
  * Subtract (r = (op1 - op2) modulo #n) two 32 byte multi-precision numbers
  * under the current prime finite field. It is to be used
  * internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to subtract from. This may alias r.
  * \param op2 The 32 byte operand to sutract off op1. This may alias r or
  *            op1.
  * \warning op1 and op2 must both be < #n.
  */
static void big_subtract_internal(Session_data * session_data, BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	uint8_t *lookup[2];
	uint8_t too_small;
	uint8_t zero[32];

	big_set_zero_internal(zero);

	/*
	assert(bigCompare(op1, n) == BIGCMP_LESS);
	assert(bigCompare(op2, n) == BIGCMP_LESS);
	*/

	too_small = big_subtract_no_modulo_internal(r, op1, op2);

	lookup[0] = zero;
	lookup[1] = session_data->n;

	big_add_variable_size_no_modulo_internal(r, r, lookup[too_small], 32);
}

/**
  * Divide a 32 byte multi-precision number by 2, truncating if necessary. It is
  * to be used internally (only by the functions of the TA itself).
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to divide by 2. This may alias r.
  */
static void big_shift_right_no_modulo_internal(BigNum256 r, const BigNum256 op1)
{
	uint8_t i;
	uint8_t carry;
	uint8_t old_carry;

	big_assign_internal(r, op1);

	old_carry = 0;

	for (i = 31; i < 32; i--)
	{
		carry = (uint8_t)(r[i] & 1);
		r[i] = (uint8_t)((r[i] >> 1) | (old_carry << 7));
		old_carry = carry;
	}
}

/**
  * Multiplies (r = op1 x op2) two multi-precision numbers of arbitrary size,
  * ignoring the current prime finite field. In other words, this does
  * multi-precision binary multiplication. It is to be used
  * internally (only by the functions of the TA itself).
  * \param r The result will be written into here. The size of the result (in
  *          number of bytes) will be op1_size + op2_size.
  * \param op1 The first operand to multiply. This cannot alias r.
  * \param op1_size The size, in number of bytes, of op1.
  * \param op2 The second operand to multiply. This cannot alias r, but it can
  *            alias op1.
  * \param op2_size The size, in number of bytes, of op2.
  * \warning This function is the speed bottleneck in an ECDSA signing
  *          operation. To speed up ECDSA signing, reimplement this in
  *          assembly and define PLATFORM_SPECIFIC_BIGMULTIPLY.
  */
static void big_multiply_variable_size_no_modulo_internal(uint8_t *r, uint8_t *op1, uint8_t op1_size, uint8_t *op2, uint8_t op2_size)
{
	uint8_t cached_op1;
	uint8_t low_carry;
	uint8_t high_carry;
	uint16_t multiply_result16;
	uint8_t multiply_result_low8;
	uint8_t multiply_result_high8;
	uint16_t partial_sum;
	uint8_t i;
	uint8_t j;

	TEE_MemFill((uint8_t*)r, (uint32_t)0, (uint32_t)(op1_size + op2_size));

	/*
	 * The multiplication algorithm here is what GMP calls the "schoolbook"
	 * method. It's also sometimes referred to as "long multiplication". It's
	 * the most straightforward method of multiplication.
	 * Note that for the operand sizes this function typically deals with,
	 * and with the platforms this code is intended to run on, the Karatsuba
	 * algorithm isn't significantly better.
	 */
	for (i = 0; i < op1_size; i++)
	{
		cached_op1 = op1[i];
		high_carry = 0;
		for (j = 0; j < op2_size; j++)
		{
			multiply_result16 = (uint16_t)((uint16_t)cached_op1 * (uint16_t)op2[j]);
			multiply_result_low8 = (uint8_t)multiply_result16;
			multiply_result_high8 = (uint8_t)(multiply_result16 >> 8);

			partial_sum = (uint16_t)((uint16_t)r[i + j] + (uint16_t)multiply_result_low8);

			r[i + j] = (uint8_t)partial_sum;
			low_carry = (uint8_t)(partial_sum >> 8);

			partial_sum = (uint16_t)((uint16_t)r[i + j + 1] + (uint16_t)multiply_result_high8 + (uint16_t)low_carry + (uint16_t)high_carry);
			r[i + j + 1] = (uint8_t)partial_sum;
			high_carry = (uint8_t)(partial_sum >> 8);
		}

		/*
		assert(high_carry == 0);
		*/
	}
}

/**
  * Multiplies (r = (op1 x op2) modulo #n) two 32 byte multi-precision
  * numbers under the current prime finite field. It is to be used
  * internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param r The 32 byte result will be written into here.
  * \param op1 The first 32 byte operand to multiply. This may alias r.
  * \param op2 The second 32 byte operand to multiply. This may alias r or
  *            op1.
  */
static void big_multiply_internal(Session_data * session_data, BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	uint8_t temp[64];
	uint8_t full_r[64];
	uint8_t remaining;

	big_multiply_variable_size_no_modulo_internal(full_r, op1, 32, op2, 32);
	/*
	 * The modular reduction is done by subtracting off some multiple of
	 * n. The upper 256 bits of r are used as an estimate for that multiple.
	 * As long as n is close to 2 ^ 256, this estimate should be very close.
	 * However, since n < 2 ^ 256, the estimate will always be an
	 * underestimate. That's okay, because the algorithm can be applied
	 * repeatedly, until the upper 256 bits of r are zero.
	 * remaining denotes the maximum number of possible non-zero bytes left in
	 * the result.
	 */
	remaining = 64;

	while (remaining > 32)
	{
		TEE_MemFill((uint8_t*)temp, (uint32_t)0, (uint32_t)64);
		/*
		 * n should be equal to 2 ^ 256 - complement_n. Therefore, subtracting
		 * off (upper 256 bits of r) * n is equivalent to setting the
		 * upper 256 bits of r to 0 and
		 * adding (upper 256 bits of r) * complement_n.
		 */
		big_multiply_variable_size_no_modulo_internal(\
			temp,
			session_data->complement_n, session_data->size_complement_n,
			&(full_r[32]), (uint8_t)(remaining - 32));

		TEE_MemFill((uint8_t*)&(full_r[32]), (uint32_t)0, (uint32_t)32);

		big_add_variable_size_no_modulo_internal(full_r,
												full_r,
												temp,
												remaining);

		/* This update of the bound is only valid for remaining > 32. */
		remaining = (uint8_t)(remaining - 32 + session_data->size_complement_n);
	}
	/*
	 * The upper 256 bits of r should now be 0. But r could still be >= n.
	 * As long as n > 2 ^ 255, at most one subtraction is
	 * required to ensure that r < n.
	 */
	big_modulo_internal(session_data, full_r, full_r);
	big_assign_internal(r, full_r);
}

/**
  * Compute the modular inverse of a 32 byte multi-precision number under
  * the current prime finite field (i.e. find r such that
  * (r x op1) modulo #n = 1). It is to be used
  * internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to find the inverse of. This may alias r.
  */
static void big_invert_internal(Session_data * session_data, BigNum256 r, BigNum256 op1)
{
	uint8_t temp[32];
	uint8_t i;
	uint8_t j;
	uint8_t byte_of_n_minus_2;
	uint8_t bit_of_n_minus_2;
	uint8_t *lookup[2];

	/*
	 * This uses Fermat's Little Theorem, of which an immediate corollary is:
	 * a ^ (p - 2) = a ^ (-1) modulo n.
	 * The Montgomery ladder method is used to perform the exponentiation.
	 */
	big_assign_internal(temp, op1);

	big_set_zero_internal(r);

	r[0] = 1;

	lookup[0] = r;
	lookup[1] = temp;

	for (i = 31; i < 32; i--)
	{
		byte_of_n_minus_2 = (session_data->n)[i];

		if (i == 0)
			byte_of_n_minus_2 = (uint8_t)(byte_of_n_minus_2 - 2);

		for (j = 0; j < 8; j++)
		{
			bit_of_n_minus_2 = (uint8_t)((byte_of_n_minus_2 & 0x80) >> 7);
			byte_of_n_minus_2 = (uint8_t)(byte_of_n_minus_2 << 1);

			/*
			 * The next two lines do the following:
			 * if (bit_of_n_minus_2)
			 * {
			 *     bigMultiply(r, r, temp);
			 *     bigMultiply(temp, temp, temp);
			 * }
			 * else
			 * {
			 *     bigMultiply(temp, r, temp);
			 *     bigMultiply(r, r, r);
			 * }
			 */

			big_multiply_internal(session_data,
								lookup[1 - bit_of_n_minus_2],
								r,
								temp);

			big_multiply_internal(session_data,
								lookup[bit_of_n_minus_2],
								lookup[bit_of_n_minus_2],
								lookup[bit_of_n_minus_2]);
		}
	}
}

/*==============================================================================
	PBKDF2 FUNCTIONS

	The GlobalPlatform hasn't published any specification for this function at
    the date (00:14:17 WEST, Sunday, 7 August 2016) but the OP-TEE  has support
    to it as an extension to GlobalPlatform TEE Internal API Specification v1.0.
    The reason why that extension is not used here it is because it not standard
    but specific to the implementation of OP-TEE and as such it wouldn't work on
    others implementation of TEE's.
    Source of pbdkf2 on OP-TEE:
    https://github.com/OP-TEE/optee_os/blob/master/documentation/extensions/crypto_pbkdf2.md
    (last acceded on 02:28:21 WEST, Sunday, 7 August 2016).
==============================================================================*/
/**
  * Derive a key using the specified password and salt, using HMAC-SHA512 as
  * the underlying pseudo-random function. The derived key length is fixed
  * at #SHA512_HASH_LENGTH bytes.
  *
  * This code here is based on section 5.3 ("PBKDF Specification") of
  * NIST SP 800-132 (obtained from
  * http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf on
  * 30 March 2013).
  * \param out A byte array where the resulting derived key will be written.
  *            This must have space for #SHA512_HASH_LENGTH bytes.
  * \param password Byte array specifying the password to use in PBKDF2.
  * \param password_length The length (in bytes) of the password.
  * \param salt Byte array specifying the salt to use in PBKDF2.
  * \param salt_length The length (in bytes) of the salt.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  * \warning salt cannot be too long; salt_length must be less than or equal
  *          to #SHA512_HASH_LENGTH - 4.
  */
static TEE_Result pbkdf2_internal(Session_data * session_data, uint8_t *out, const uint8_t *password, const unsigned int password_length, const uint8_t *salt, const unsigned int salt_length)
{
	TEE_Result result = TEE_SUCCESS;
	uint8_t u[SHA512_HASH_LENGTH];
	uint8_t hmac_result[SHA512_HASH_LENGTH];
	unsigned int u_length;
	uint32_t i;
	unsigned int j;

	/* 'Clearing' the output buffer */
	TEE_MemFill((uint8_t*)out, 0, (uint32_t)SHA512_HASH_LENGTH);

	TEE_MemFill((uint8_t*)u, 0, (uint32_t)sizeof(u));

	/* Checking if salt is too long */
	if (salt_length > (SHA512_HASH_LENGTH - 4))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Input text length */
	u_length = salt_length;

	/* Copy the salt */
	TEE_MemMove((uint8_t*)u, (uint8_t*)salt, u_length);

	write_u32_big_endian_internal(&(u[u_length]), 1);

	u_length += 4;

	/* Set the HMAC-SHA-512 key */
	result = set_hmac_sha512_key_internal(session_data,
										(uint8_t*)password,
										(unsigned int)password_length);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to set the HMAC-SHA-512 operation key: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

	for (i = 0; i < PBKDF2_ITERATIONS; i++)
	{
		result = hmac_sha512_internal(session_data, hmac_result, u, u_length);

		if (result != TEE_SUCCESS)
	    {
	    	#ifdef OP_TEE_TA
	    	DMSG("Failed to set do HMAC-SHA-512 operation : 0x%x", result);
	    	#endif
	    	goto cleanup1;
	    }

		TEE_MemMove((uint8_t*)u, (uint8_t*)hmac_result, sizeof(u));

		u_length = SHA512_HASH_LENGTH;

		for (j = 0; j < SHA512_HASH_LENGTH; j++)
			out[j] ^= u[j];
	}

	/* Resources cleanup */
	cleanup1:
		return result;
}

/**
  * Wrapper of pbkdf2_internal() for a CA command.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result pbkdf2(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Output buffer where the result will be written to.
	 * [OUT] params[0].memref.size   -> Size of the output buffer.
	 * [IN]  params[1].memref.buffer -> Password.
	 * [IN]  params[1].memref.size   -> Length of the password.
	 * [IN]  params[2].memref.buffer -> Salt.
	 * [IN]  params[2].memref.size   -> Length of the salt.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL
		|| params[2].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	result = pbkdf2_internal(session_data,
							(uint8_t*)(params[0].memref.buffer),
							(uint8_t*)(params[1].memref.buffer),
							(unsigned int)(params[1].memref.size),
							(uint8_t*)(params[2].memref.buffer),
							(unsigned int)(params[2].memref.size));

	return result;
}

/*==============================================================================
	ECDSA FUNCTIONS

	GlobalPlatform supports ECDSA as an valid asymmetric signature scheme but
	not all TEE that implement the GlobalPlatform "TEE Internal Core API
	Specification v1.1" may support it so here it was opted by implementing the
	algorithm instead of using the one provided by the OP-TEE.
==============================================================================*/
/**
  * Convert a point from affine coordinates to Jacobian coordinates. This
  * is very fast. It is to be used
  * internally (only by the functions of the TA itself).
  * \param out The destination point (in Jacobian coordinates).
  * \param in The source point (in affine coordinates).
  */
static void affine_to_jacobian_internal(PointJacobian *out, PointAffine *in)
{
	out->is_point_at_infinity = in->is_point_at_infinity;

	/*
	* If out->is_point_at_infinity != 0, the rest of this function consists
	* of dummy operations
	*/
	big_assign_internal(out->x, in->x);
	big_assign_internal(out->y, in->y);

	big_set_zero_internal(out->z);

	out->z[0] = 1;
}

/**
  * Convert a point from Jacobian coordinates to affine coordinates. This
  * is very slow because it involves inversion (division). It is to be used
  * internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param out The destination point (in affine coordinates).
  * \param in The source point (in Jacobian coordinates).
  */
static NOINLINE void jacobian_to_affine_internal(Session_data * session_data, PointAffine *out, PointJacobian *in)
{
	uint8_t s[32];
	uint8_t t[32];

	out->is_point_at_infinity = in->is_point_at_infinity;

	/*
	* If out->is_point_at_infinity != 0, the rest of this function consists
	* of dummy operations.
	*/
	big_multiply_internal(session_data, s, in->z, in->z);
	big_multiply_internal(session_data, t, s, in->z);

	/* Now s = z ^ 2 and t = z ^ 3. */
	big_invert_internal(session_data, s, s);
	big_invert_internal(session_data, t, t);

	big_multiply_internal(session_data, out->x, in->x, s);
	big_multiply_internal(session_data, out->y, in->y, t);
}

/**
  * Double (p = 2 x p) the point p (which is in Jacobian coordinates), placing
  * the result back into p.
  * The formulae for this function were obtained from the article:
  * "Software Implementation of the NIST Elliptic Curves Over Prime Fields",
  * obtained from:
  * http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8619&rep=rep1&type=pdf
  * on 16-August-2011. See equations (2) ("doubling in Jacobian coordinates")
  * from section 4 of that article. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param p The point (in Jacobian coordinates) to double.
  */
static NOINLINE void point_double_internal(Session_data * session_data, PointJacobian *p)
{
	uint8_t t[32];
	uint8_t u[32];

	/*
	* If p->is_point_at_infinity != 0, then the rest of this function will
	* consist of dummy operations. Nothing else needs to be done since
	* 2O = O.
	*
	* If y is zero then the tangent line is vertical and never hits the
	* curve, therefore the result should be O. If y is zero, the rest of this
	* function will consist of dummy operations.
	*/
	p->is_point_at_infinity |= big_is_zero_internal(p->y);

	big_multiply_internal(session_data, p->z, p->z, p->y);

	big_add_internal(session_data, p->z, p->z, p->z);

	big_multiply_internal(session_data, p->y, p->y, p->y);
	big_multiply_internal(session_data, t, p->y, p->x);

	big_add_internal(session_data, t, t, t);
	big_add_internal(session_data, t, t, t);

	/* t iTZs now 4.0 * p->x * p->y ^ 2. */
	big_multiply_internal(session_data, p->x, p->x, p->x);

	big_assign_internal(u, p->x);

	big_add_internal(session_data, u, u, u);
	big_add_internal(session_data, u, u, p->x);

	/*
	* u is now 3.0 * p->x ^ 2.
	* For curves with a != 0, a * p->z ^ 4 needs to be added to u.
	* But since a == 0 in secp256k1, we save 2 squarings and 1
	* multiplication.
	*/
	big_multiply_internal(session_data, p->x, u, u);

	big_subtract_internal(session_data, p->x, p->x, t);
	big_subtract_internal(session_data, p->x, p->x, t);
	big_subtract_internal(session_data, t, t, p->x);

	big_multiply_internal(session_data, t, t, u);
	big_multiply_internal(session_data, p->y, p->y, p->y);

	big_add_internal(session_data, p->y, p->y, p->y);
	big_add_internal(session_data, p->y, p->y, p->y);
	big_add_internal(session_data, p->y, p->y, p->y);

	big_subtract_internal(session_data, p->y, t, p->y);
}

/**
  * Add (p1 = p1 + p2) the point p2 to the point p1, storing the result back
  * into p1.
  * Mixed coordinates are used because it reduces the number of squarings and
  * multiplications from 16 to 11.
  * See equations (3) ("addition in mixed Jacobian-affine coordinates") from
  * section 4 of that article described in the comments to pointDouble().
  * junk must point at some memory area to redirect dummy writes to. The dummy
  * writes are used to encourage this function's completion time to be
  * independent of its parameters. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.p
  * \param p1 The point (in Jacobian coordinates) to add p2 to.
  * \param junk Pointer to a dummy variable which may receive dummy writes.
  * \param p2 The point (in affine coordinates) to add to p1.
  */
static NOINLINE void point_add_internal(Session_data * session_data, PointJacobian *p1, PointJacobian *junk, PointAffine *p2)
{
	uint8_t s[32];
	uint8_t t[32];
	uint8_t u[32];
	uint8_t v[32];
	uint8_t is_O;
	uint8_t is_O2;
	uint8_t cmp_xs;
	uint8_t cmp_yt;
	PointJacobian *lookup[2];

	lookup[0] = p1;
	lookup[1] = junk;

	/*
	 * O + p2 == p2.
	 * If p1 is O, then copy p2 into p1 and redirect all writes to the dummy
	 * write area.
	 * The following line does: "is_O = p1->is_point_at_infinity ? 1 : 0;".
	 */
	is_O = (uint8_t)((((uint16_t)(-(int)p1->is_point_at_infinity)) >> 8) & 1);

	affine_to_jacobian_internal(lookup[1 - is_O], p2);

	p1 = lookup[is_O];

	lookup[0] = p1; /* p1 might have changed */

	/*
	 * p1 + O == p1.
	 * If p2 is O, then redirect all writes to the dummy write area. This
	 * preserves the value of p1.
	 * The following line does: "is_O2 = p2->is_point_at_infinity ? 1 : 0;".
	 */
	is_O2 = (uint8_t)((((uint16_t)(-(int)p2->is_point_at_infinity)) >> 8) & 1);

	p1 = lookup[is_O2];

	lookup[0] = p1; /* p1 might have changed */

	big_multiply_internal(session_data, s, p1->z, p1->z);
	big_multiply_internal(session_data, t, s, p1->z);
	big_multiply_internal(session_data, t, t, p2->y);
	big_multiply_internal(session_data, s, s, p2->x);

	/*
	 * The following two lines do:
	 * "cmp_xs = bigCompare(p1->x, s) == BIGCMP_EQUAL ? 0 : 0xff;".
	 */
	cmp_xs = (uint8_t)(big_compare_internal(p1->x, s) ^ BIGCMP_EQUAL);
	cmp_xs = (uint8_t)(((uint16_t)(-(int)cmp_xs)) >> 8);

	/*
	 * The following two lines do:
	 * "cmp_yt = bigCompare(p1->y, t) == BIGCMP_EQUAL ? 0 : 0xff;".
	 */
	cmp_yt = (uint8_t)(big_compare_internal(p1->y, t) ^ BIGCMP_EQUAL);
	cmp_yt = (uint8_t)(((uint16_t)(-(int)cmp_yt)) >> 8);

	/*
	 * The following branch can never be taken when calling pointMultiply(),
	 * so its existence doesn't compromise timing regularity.
	 */
	if ((cmp_xs | cmp_yt | is_O | is_O2) == 0)
	{
		/* Points are actually the same; use point doubling. */
		point_double_internal(session_data, p1);
		return;
	}

	/*
	 * p2 == -p1 when p1->x == s and p1->y != t.
	 * If p1->is_point_at_infinity is set, then all subsequent operations in
	 * this function become dummy operations.
	 */
	p1->is_point_at_infinity = (uint8_t)(p1->is_point_at_infinity | (~cmp_xs & cmp_yt & 1));

	big_subtract_internal(session_data, s, s, p1->x);

	/* s now contains p2->x * p1->z ^ 2 - p1->x. */
	big_subtract_internal(session_data, t, t, p1->y);

	/* t now contains p2->y * p1->z ^ 3 - p1->y. */
	big_multiply_internal(session_data, p1->z, p1->z, s);
	big_multiply_internal(session_data, v, s, s);
	big_multiply_internal(session_data, u, v, p1->x);
	big_multiply_internal(session_data, p1->x, t, t);
	big_multiply_internal(session_data, s, s, v);

	big_subtract_internal(session_data, p1->x, p1->x, s);
	big_subtract_internal(session_data, p1->x, p1->x, u);
	big_subtract_internal(session_data, p1->x, p1->x, u);
	big_subtract_internal(session_data, u, u, p1->x);

	big_multiply_internal(session_data, u, u, t);
	big_multiply_internal(session_data, s, s, p1->y);

	big_subtract_internal(session_data, p1->y, u, s);
}

/**
  * Set field parameters to be those defined by the prime number p which
  * is used in secp256k1. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  */
static void set_field_to_p_internal(Session_data * session_data)
{
  big_set_field_internal(session_data, secp256k1_p,
  						secp256k1_complement_p,
  						sizeof(secp256k1_complement_p));
}


/**
  * Set field parameters to be those defined by the prime number n which
  * is used in secp256k1. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  */
static void set_field_to_n_internal(Session_data * session_data)
{
	big_set_field_internal(session_data,
							secp256k1_n,
							secp256k1_complement_n,
							sizeof(secp256k1_complement_n));
}

/**
  * Perform scalar multiplication (p = k x p) of the point p by the scalar k.
  * The result will be stored back into p. The multiplication is
  * accomplished by repeated point doubling and adding of the
  * original point. All multi-precision integer operations are done under
  * the prime finite field specified by #secp256k1_p. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param p The point (in affine coordinates) to multiply.
  * \param k The 32 byte multi-precision scalar to multiply p by.
  */
static void point_multiply_internal(Session_data *session_data, PointAffine *p, BigNum256 k)
{
	PointJacobian accumulator;
	PointJacobian junk;
	PointAffine always_point_at_infinity; /* for dummy operations */
	uint8_t i;
	uint8_t j;
	uint8_t one_byte;
	uint8_t one_bit;
	PointAffine *lookup_affine[2];

	TEE_MemFill((PointJacobian*)&accumulator,
				(uint32_t)0,
				(uint32_t)sizeof(PointJacobian));

	TEE_MemFill((PointJacobian*)&junk,
				(uint32_t)0,
				(uint32_t)sizeof(PointJacobian));

	TEE_MemFill((PointAffine*)&always_point_at_infinity,
				(uint32_t)0,
				(uint32_t)sizeof(PointAffine));

	set_field_to_p_internal(session_data);

	/*
	* The Montgomery ladder method can't be used here because it requires
	* point addition to be done in pure Jacobian coordinates. Point addition
	* in pure Jacobian coordinates would make point multiplication about
	* 26% slower. Instead, dummy operations are used to make point
	* multiplication a constant time operation. However, the use of dummy
	* operations does make this code more susceptible to fault analysis -
	* by introducing faults where dummy operations may occur, an attacker
	* can determine whether bits in the private key are set or not.
	* So the use of this code is not appropriate in situations where fault
	* analysis can occur.
	*/
	accumulator.is_point_at_infinity = 1;
	always_point_at_infinity.is_point_at_infinity = 1;
	lookup_affine[1] = p;
	lookup_affine[0] = &always_point_at_infinity;

	for (i = 31; i < 32; i--)
	{
		one_byte = k[i];

		for (j = 0; j < 8; j++)
		{
			point_double_internal(session_data, &accumulator);
			one_bit = (uint8_t)((one_byte & 0x80) >> 7);

			point_add_internal(session_data,
								&accumulator,
								&junk,
								lookup_affine[one_bit]);

			one_byte = (uint8_t)(one_byte << 1);
		}
	}

	jacobian_to_affine_internal(session_data, p, &accumulator);
}

/**
  * Wrapper of point_multiply_internal() for a CA command. This function is not
  * really needed for the correct functioning of the wallet it is and should
  * only be used for testing purposes.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result point_multiply_test(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
     * Expected:
     * [IO]  params[0].memref.buffer -> The point (in affine coordinates) to multiply.
     * [IO]  params[0].memref.size   -> Size of the point.
     * [IN]  params[1].memref.buffer -> The 32 byte multi-precision scalar to multiply p by.
     * [IN]  params[1].memref.size   -> Size of the scalar point.
     */
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
									TEE_PARAM_TYPE_MEMREF_INPUT,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	point_multiply_internal(session_data,
							(PointAffine*)(params[0].memref.buffer),
							(BigNum256)(params[1].memref.buffer));

	return result;
}

/**
  * Set a point to the base point of secp256k1.
  * \param p The point to set.
  */
static void set_to_g_internal(PointAffine *p)
{
	uint8_t buffer[32];
	uint8_t i;

	p->is_point_at_infinity = 0;

	for (i = 0; i < 32; i++)
		buffer[i] = LOOKUP_BYTE(secp256k1_Gx[i]);

	big_assign_internal(p->x, (BigNum256)buffer);

	for (i = 0; i < 32; i++)
		buffer[i] = LOOKUP_BYTE(secp256k1_Gy[i]);

	big_assign_internal(p->y, (BigNum256)buffer);
}

/**
  * Wrapper of set_to_g_internal() for a CA command. This function is not
  * really needed for the correct functioning of the wallet it is and should
  * only be used for testing purposes.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result set_to_g_test(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
     * Expected:
     * [OUT] params[0].memref.buffer -> The point to set.
     * [OUT] params[0].memref.size   -> Size of the point to set.
     */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	(void)&session_data;

	/* Some sanity checks */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	set_to_g_internal((PointAffine*)(params[0].memref.buffer));

	return result;
}

/**
  * Serialise an elliptic curve point in a manner which is Bitcoin-compatible.
  * This means using the serialisation rules in:
  * "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
  * 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
  * sections 2.3.2 ("OctetString-to-BitString Conversion") and
  * 2.3.3 ("EllipticCurvePoint-to-OctetString Conversion").
  * The document basically says that integers should be represented big-endian
  * and that a prefix byte should be perpended to indicate that the public key
  * is compressed or not.
  * \param out Where the serialised point will be written to. This must be a
  *            byte array with space for at least #ECDSA_MAX_SERIALISE_SIZE
  *            bytes.
  * \param point The elliptic point curve to serialise.
  * \param do_compress Whether to apply point compression - this will reduce
  *                    the size of public keys and hence transactions.
  *                    As of 2014, all Bitcoin clients out there are able to
  *                    decompress points, so it should be safe to always
  *                    compress points.
  * \return The number of bytes written to out.
  */
static uint8_t ecdsa_serialise_internal(uint8_t *out, const PointAffine *point, const bool do_compress)
{
	PointAffine temp;

	TEE_MemMove((PointAffine*)&temp, (PointAffine*)point, (uint32_t)sizeof(temp)); /* Need temp for endian reversing */

	if (temp.is_point_at_infinity)
	{
		/* Special case for point at infinity. */
		out[0] = 0x00;

		return 1;
	}
	else if (!do_compress)
	{
		/* Uncompressed point. */
		out[0] = 0x04;

		swap_endian256_internal(temp.x);
		swap_endian256_internal(temp.y);

		TEE_MemMove((uint8_t*)&(out[1]), (uint8_t*)(temp.x), 32);
		TEE_MemMove((uint8_t*)&(out[33]), (uint8_t*)(temp.y), 32);

		return 65;
	}
	else
	{
		/* Compressed point. */
		if ((temp.y[0] & 1) != 0)
			out[0] = 0x03; /* is odd */
		else
			out[0] = 0x02; /* is not odd */

		swap_endian256_internal(temp.x);

		TEE_MemMove((uint8_t*)&(out[1]), (uint8_t*)(temp.x), 32);

		return 33;
	}
}

/**
  * Wrapper of ecdsa_serialise_internal() for a CA command. This function is not
  * really needed for the correct functioning of the wallet it is and should
  * only be used for testing purposes.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result ecdsa_serialise(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
     * Expected:
     * [OUT] params[0].memref.buffer -> The point to set..
     * [OUT] params[0].memref.size   -> Size of the point to set.
     * [IN]  params[1].memref.buffer -> The point to set..
     * [IN]  params[1].memref.size   -> Size of the point to set.
     * [IN]  params[2].value.a       -> Boolean with info about compression.
     * [OUT] params[2].value.b       -> The number of bytes written to out.
     */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE);
	(void)&session_data;

	/* Some sanity checks */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	set_to_g_internal((PointAffine*)(params[0].memref.buffer));

	params[2].value.b = (uint32_t)ecdsa_serialise_internal(
									(uint8_t*)(params[0].memref.buffer),
									(PointAffine*)(params[1].memref.buffer),
									(bool)(params[2].value.a));

	return result;
}

/** Create a deterministic ECDSA signature of a given message (digest) and
  * private key.
  * This is an implementation of the algorithm described in the document
  * "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
  * 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
  * section 4.1.3 ("Signing Operation"). The ephemeral private key "k" will
  * be deterministically generated according to RFC 6979.
  * \param session_data A data pointer to a session context.
  * \param private_key The private key to use in the signing operation,
  *                    represented as a 32 byte multi-precision number.
  * \param params A pointer to an array of four parameters. See ecdsa_sign().
  */
static void ecdsa_sign_internal(Session_data * session_data, uint8_t * private_key, TEE_Param params[4])
{
	HMACDRBGState state;
	PointAffine big_r;
	uint8_t seed_material[32 + SHA256_HASH_LENGTH];
	uint8_t k[32];

	/*
	 * From RFC 6979, section 3.3a:
	 * seed_material = int2octets(private_key) || bits2octets(hash)
	 * int2octets and bits2octets both interpret the number as big-endian.
	 * However, both the private_key and hash parameters are BigNum256, which
	 * is little-endian.
	 */
	big_assign_internal(seed_material, private_key);

	swap_endian256_internal(seed_material); /* little-endian -> big-endian */

	big_assign_internal(&(seed_material[32]),
						(BigNum256)(params[2].memref.buffer));

	swap_endian256_internal(&(seed_material[32]));  /* little-endian -> big-endian */

	drbg_instantiate_internal(session_data, &state,
							seed_material,
							sizeof(seed_material));

	while (true)
	{
		drbg_generate_internal(session_data, k, &state, 32, NULL, 0);

		/*
		 * From RFC 6979, section 3.3b, the output of the DRBG is run through
		 * the bits2int function, which interprets the output as a big-endian
		 * integer. However, functions in bignum256.c expect a little-endian
		 * integer.
		 */
		swap_endian256_internal(k); /* big-endian -> little-endian */

		/*
		 * This is one of many data-dependent branches in this function. They do
		 * not compromise timing attack resistance because these branches are
		 * expected to occur extremely infrequently.
		 */
		if (big_is_zero_internal(k))
			continue;

		if (big_compare_internal(k, (BigNum256)secp256k1_n) != BIGCMP_LESS)
			continue;

		/* Compute ephemeral elliptic curve key pair (k, big_r). */
		set_to_g_internal(&big_r);

		point_multiply_internal(session_data, &big_r, k);

		/* big_r now contains k * G. */
		set_field_to_n_internal(session_data);

		big_modulo_internal(session_data,
							(BigNum256)(params[0].memref.buffer),
							big_r.x);

		/* r now contains (k * G).x (mod n). */
		if (big_is_zero_internal((BigNum256)(params[0].memref.buffer)))
			continue;

		big_multiply_internal(session_data,
							(BigNum256)(params[1].memref.buffer),
							(BigNum256)(params[0].memref.buffer),
							private_key);

		big_modulo_internal(session_data,
							big_r.y,
							(BigNum256)(params[2].memref.buffer)); /* use big_r.y as temporary */

		big_add_internal(session_data,
						(BigNum256)(params[1].memref.buffer),
						(BigNum256)(params[1].memref.buffer),
						big_r.y);

		big_invert_internal(session_data, big_r.y, k);

		big_multiply_internal(session_data,
							(BigNum256)(params[1].memref.buffer),
							(BigNum256)(params[1].memref.buffer),
							big_r.y);

		/* s now contains (hash + (r * private_key)) / k (mod n). */
		if (big_is_zero_internal((BigNum256)(params[1].memref.buffer)))
			continue;

		/*
		 * Canonicalise s by negating it if s > secp256k1_n / 2.
		 * See https://github.com/bitcoin/bitcoin/pull/3016 for more info.
		 */
		big_shift_right_no_modulo_internal(k, (const BigNum256)secp256k1_n); /* use k as temporary */

		if (big_compare_internal((BigNum256)(params[1].memref.buffer), k) == BIGCMP_GREATER)
			big_subtract_no_modulo_internal((BigNum256)(params[1].memref.buffer),
											(BigNum256)secp256k1_n,
											(BigNum256)(params[1].memref.buffer));

		break;
  	}
}

/** Wrapper of ecdsa_sign_internal() for a CA command.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result ecdsa_sign(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	WalletErrors wallet_error = WALLET_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint8_t private_key[32];

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> The "r" component of the signature.
	 * [OUT] params[0].memref.size   -> Size of "r".
	 * [OUT] params[1].memref.buffer -> The "s" component of the signature.
	 * [OUT] params[1].memref.size   -> Size of "s".
	 * [IN]  params[2].memref.buffer -> The message digest of the message to sign.
	 * [IN]  params[2].memref.size   -> Size of message.
	 * [IN]  params[3].value.a   	 -> AddressHandle of the private key.
	 * [OUT] params[3].value.b   	 -> WalletErrors return of get private key.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT);

	/* Some sanity checks */
	if (param_types != exp_param_types
	 || params[0].memref.buffer == NULL
	 || params[1].memref.buffer == NULL
	 || params[2].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get the private key */
	wallet_error = get_private_key_internal(session_data,
											private_key,
											(AddressHandle)(params[3].value.a));

	if (wallet_error != WALLET_NO_ERROR)
	{
		result = TEE_ERROR_BAD_STATE;
		goto cleanup1;
	}

	ecdsa_sign_internal(session_data, private_key, params);

	/* Resources cleanup */
	cleanup1:
		params[3].value.b = (uint32_t)wallet_error;
		return result;
}

/** Wrapper of ecdsa_sign_internal() for a CA command. This function differs
  * from the ecdsa_sign() on the private key used. The former one used the
  * private key stored in the TA and this one used a private key passed by the
  * CA. This function is not needed for the correct functioning of the wallet it
  * is and should only be used for testing purposes.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result ecdsa_sign_test(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> The "r" component of the signature.
	 * [OUT] params[0].memref.size   -> Size of "r".
	 * [OUT] params[1].memref.buffer -> The "s" component of the signature.
	 * [OUT] params[1].memref.size   -> Size of "s".
	 * [IN]  params[2].memref.buffer -> The message digest of the message to sign.
	 * [IN]  params[2].memref.size   -> Size of message.
	 * [IN]  params[3].memref.buffer -> Private key.
     * [IN]  params[3].memref.size   -> Size of the private key.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT);

	/* Some sanity checks */
	if (param_types != exp_param_types
	 || params[0].memref.buffer == NULL
	 || params[1].memref.buffer == NULL
	 || params[2].memref.buffer == NULL
	 || params[3].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Here it will be used the private key passed by the CA */
	ecdsa_sign_internal(session_data,
						(BigNum256)(params[3].memref.buffer),
						params);

	return result;
}

/*==============================================================================
	PRANDOM FUNCTIONS
==============================================================================*/
/**
  * Use a combination of cryptographic primitives to deterministically
  * generate a new public key.
  *
  * The generator uses the algorithm described in
  * https://en.bitcoin.it/wiki/BIP_0032, accessed 12-November-2012 under the
  * "Specification" header. The generator generates uncompressed keys.
  * This function is not needed for the correct functioning of the wallet it
  * is used for testing purposes.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */

static TEE_Result generate_deterministic_public_key_test(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint8_t hmac_message[69];   /* 04 (1 byte) + x (32 bytes) + y (32 bytes) + num (4 bytes) */
	uint8_t hash[SHA512_HASH_LENGTH];
    BigNum256 i_l;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> The generated public key.
	 * [OUT] params[0].memref.size   -> Size of the generated public key.
	 * [IN]  params[1].memref.buffer -> The parent public key.
	 * [IN]  params[1].memref.size   -> Length of the parent public key.
	 * [IN]  params[2].memref.buffer -> Byte array of length 32 containing the
	 *									BIP 0032 chain code.
	 * [IN]  params[2].memref.size   -> Length of the the array.
	 * [IN]  params[3].value.a   	 -> The counter.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INPUT);

	/* Some sanity checks */
	if (param_types != exp_param_types
	 || params[0].memref.buffer == NULL
	 || params[1].memref.buffer == NULL
	 || params[2].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	hmac_message[0] = 0x04;

	TEE_MemMove(
		(uint8_t*)&(hmac_message[1]),
		(uint8_t*)(((PointAffine*)(params[1].memref.buffer))->x),
		(uint32_t)32);

	swap_endian256_internal(&(hmac_message[1]));

	TEE_MemMove(
		(uint8_t*)&(hmac_message[33]),
		(uint8_t*)(((PointAffine*)(params[1].memref.buffer))->y),
		(uint32_t)32);

	swap_endian256_internal(&(hmac_message[33]));

	write_u32_big_endian_internal(&(hmac_message[65]), params[3].value.a );

	result = set_hmac_sha512_key_internal(session_data,
										(uint8_t*)(params[2].memref.buffer),
										32);

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to set the HMAC-SHA-512 operation key: 0x%x", result);
    	#endif
    	goto cleanup1;
    }

	result = hmac_sha512_internal(session_data,
								hash,
								hmac_message,
								sizeof(hmac_message));

	if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to set do HMAC-SHA-512 operation : 0x%x", result);
    	#endif
    	goto cleanup1;
    }

	set_field_to_n_internal(session_data);

	i_l = (BigNum256)hash;

	swap_endian256_internal(i_l);

	big_modulo_internal(session_data, i_l, i_l);

	TEE_MemMove(
		(PointAffine*)(params[0].memref.buffer),
		(PointAffine*)(params[1].memref.buffer),
		(uint32_t)sizeof(PointAffine));

	point_multiply_internal(session_data,
							(PointAffine*)(params[0].memref.buffer),
							i_l);

	cleanup1:
		return result;
}

/** Set the parent public key for the deterministic key generator (see
  * generateDeterministic256()). This function will speed up subsequent calls
  * to generateDeterministic256(), by allowing it to use a cached parent
  * public key. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  * \param parent_private_key The parent private key, from which the parent
  *                           public key will be derived. Note that this
  *                           should be in little-endian format.
  */
static void set_parent_public_key_from_private_key_internal(Session_data * session_data, BigNum256 parent_private_key)
{
    set_to_g_internal(&(session_data->cached_parent_public_key));

    point_multiply_internal(session_data,
    						&(session_data->cached_parent_public_key),
    						parent_private_key);

    session_data->is_cached_parent_public_key_valid = true;
}

/** Clear the parent public key cache (see #parent_private_key). This should
  * be called whenever a wallet is unloaded, so that subsequent calls to
  * generate_deterministic256_internal() don't result in addresses from the old
  * wallet. It is
  * to be used internally (only by the functions of the TA itself).
  * \param session_data A data pointer to a session context.
  */
static void clear_parent_public_key_cache_internal(Session_data * session_data)
{
	/* Just to be sure */
    TEE_MemFill(
    		(PointAffine*)&(session_data->cached_parent_public_key),
    		(uint32_t)0xff,
    		(uint32_t)sizeof(session_data->cached_parent_public_key));

    TEE_MemFill(
    		(PointAffine*)&(session_data->cached_parent_public_key),
    		(uint32_t)0,
    		(uint32_t)sizeof(session_data->cached_parent_public_key));

    session_data->is_cached_parent_public_key_valid = false;
}

/** Wrapper of clear_parent_public_key_cache_internal() for a CA command.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result clear_parent_public_key_cache(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)&params;

	clear_parent_public_key_cache_internal(session_data);

	return result;
}

/**
  * Generates random bytes.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result generate_random_bytes(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer to write the random bytes.
	 * [OUT] params[0].memref.size   -> Number of random bytes to generate.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Unused parameters */
	(void)&session_data;

	/* Some sanity checks */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
     * Write the random data in params[0].memref.buffer.
     */
    TEE_GenerateRandom((uint8_t*)(params[0].memref.buffer),
    					(uint32_t)(params[0].memref.size));

	return result;
}

/** Use a combination of cryptographic primitives to deterministically
  * generate a new 256 bit number.
  *
  * The generator uses the algorithm described in
  * https://en.bitcoin.it/wiki/BIP_0032, accessed 12-November-2012 under the
  * "Specification" header. The generator generates uncompressed keys.
  * This function is only used by the TA itself.
  * \param session_data A data pointer to a session context.
  * \param out The generated 256 bit number will be written here.
  * \param seed Should point to a byte array of length #SEED_LENGTH containing
  *             the seed for the pseudo-random number generator. While the
  *             seed can be considered as an arbitrary array of bytes, the
  *             bytes of the array also admit the following interpretation:
  *             the first 32 bytes are the parent private key in big-endian
  *             format, and the next 32 bytes are the chain code (endian
  *             independent).
  * \param num A counter which determines which number the pseudo-random
  *            number generator will output.
  * \param test A boolean to indicate if this function is called for testing
  *				purposes so it can copy the chain code.
  * \param test_chain_code Where the chain code will be copied in a testing case
  * \param test_chain_code_size Size of the test_chain_code.
  * \return false upon success, true if the specified seed is not valid (will
  *         produce degenerate private keys).
  */
static bool generate_deterministic256_internal(Session_data * session_data, BigNum256 out, const uint8_t *seed, const uint32_t num, bool test, BigNum256 test_chain_code, uint32_t test_chain_code_size)
{
	TEE_Result result = TEE_SUCCESS;
    BigNum256 i_l;
    uint8_t k_par[32];
    uint8_t hash[SHA512_HASH_LENGTH];
    uint8_t hmac_message[69]; /* 04 (1 byte) + x (32 bytes) + y (32 bytes) + num (4 bytes) */

    set_field_to_n_internal(session_data);

    TEE_MemMove((uint8_t*)k_par, (uint8_t*)seed, (uint32_t)32);

    swap_endian256_internal(k_par); /* Since seed is big-endian */

    big_modulo_internal(session_data, k_par, k_par); /* Just in case */

    /*
     * k_par cannot be 0. If it is zero, then the output of this generator
     * will always be 0.
     */
    if (big_is_zero_internal(k_par))
        return true; /* Invalid seed */

    if (!(session_data->is_cached_parent_public_key_valid))
        set_parent_public_key_from_private_key_internal(session_data, k_par);

    /*
     * BIP 0032 specifies that the public key should be represented in a way
     * that is compatible with "SEC 1: Elliptic Curve Cryptography" by
     * Certicom research, obtained 15-August-2011 from:
     * http://www.secg.org/collateral/sec1_final.pdf section 2.3 ("Data Types
     * and Conversions"). The gist of it is: 0x04, followed by x, then y in
     * big-endian format.
     * TODO: Remove this all and implement updated BIP 32
     */
    hmac_message[0] = 0x04;

    TEE_MemMove((uint8_t*)&(hmac_message[1]),
    			(uint8_t*)(session_data->cached_parent_public_key.x),
    			(uint32_t)32);

    swap_endian256_internal(&(hmac_message[1]));

    TEE_MemMove((uint8_t*)&(hmac_message[33]),
    			(uint8_t*)(session_data->cached_parent_public_key.y),
    			(uint32_t)32);

    swap_endian256_internal(&(hmac_message[33]));

    write_u32_big_endian_internal(&(hmac_message[65]), num);

    result = set_hmac_sha512_key_internal(session_data, &(seed[32]), 32);

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to set the HMAC-SHA-512 operation key: 0x%x", result);
    	#endif
    	return true;
    }

    result = hmac_sha512_internal(session_data,
    							hash,
    							hmac_message,
    							sizeof(hmac_message));

    if (result != TEE_SUCCESS)
    {
    	#ifdef OP_TEE_TA
    	DMSG("Failed to set do HMAC-SHA-512 operation : 0x%x", result);
    	#endif
    	return true;
    }

    set_field_to_n_internal(session_data);

    i_l = (BigNum256)hash;

    swap_endian256_internal(i_l);     /* Since hash is big-endian */

    big_modulo_internal(session_data, i_l, i_l);    /* Just in case */

    big_multiply_internal(session_data, out, i_l, k_par);

    if (test)
        TEE_MemMove((BigNum256)test_chain_code,
        			(uint8_t*)&(hash[32]),
        			(uint32_t)test_chain_code_size);

    return false;   /* Success */
}

/**
  * Wrapper for generate_deterministic256_internal() for a CA command.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result generate_deterministic256(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	bool gd256_result;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> The generated 256 bit number.
	 * [OUT] params[0].memref.size   -> Size of the generated number.
	 * [IN]  params[1].memref.buffer -> The seed for the pseudo-random number
	 *									generator
	 * [IN]  params[1].memref.size   -> Length of the seed.
	 * [IN]  params[2].value.a   	 -> The counter.
	 * [OUT] params[2].value.b   	 -> Result.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
	 || params[0].memref.buffer == NULL
	 || params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	gd256_result = generate_deterministic256_internal(
							session_data,
							(BigNum256)(params[0].memref.buffer),
							(uint8_t*)(params[1].memref.buffer),
							params[2].value.a,
							false,
							NULL,
							0);

	params[2].value.b = (uint32_t)gd256_result;

	return result;
}

/**
  * Wrapper for generate_deterministic256_internal() for a CA command. This
  * function differs from generate_deterministic256() because it allows to get
  * the chain code. This function is not needed for the correct functioning of
  * the wallet it is and should only be used for testing purposes.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result generate_deterministic256_test(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	bool gd256_result;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> The generated 256 bit number.
	 * [OUT] params[0].memref.size   -> Size of the generated number.
	 * [IN]  params[1].memref.buffer -> The seed for the pseudo-random number
	 *									generator
	 * [IN]  params[1].memref.size   -> Length of the seed.
	 * [IN]  params[2].value.a   	 -> The counter.
	 * [OUT] params[2].value.b   	 -> Result.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT);

	/* Some sanity checks */
	if (param_types != exp_param_types
	 || params[0].memref.buffer == NULL
	 || params[1].memref.buffer == NULL
	 || params[3].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	gd256_result = generate_deterministic256_internal(
							session_data,
							(BigNum256)(params[0].memref.buffer),
							(uint8_t*)(params[1].memref.buffer),
							params[2].value.a,
							true,
							(BigNum256)(params[3].memref.buffer),
							(uint32_t)(params[3].memref.size));

	params[2].value.b = (uint32_t)gd256_result;

	return result;
}

/** Calculate the entropy pool checksum of an entropy pool state.
  * Without integrity checks, an attacker with access to the persistent
  * entropy pool area (in non-volatile memory) could reduce the amount of
  * entropy in the persistent pool. Even if the persistent entropy pool is
  * encrypted, an attacker could reduce the amount of entropy in the pool down
  * to the amount of entropy in the encryption key, which is probably much
  * less than 256 bits.
  * If the persistent entropy pool is unencrypted, then the checksum provides
  * no additional security. In that case, the checksum is only used to check
  * that non-volatile memory is working as expected.
  * \param out The checksum will be written here. This must be a byte array\
  *            with space for #POOL_CHECKSUM_LENGTH bytes.
  * \param pool_state The entropy pool state to calculate the checksum of.
  *                   This must be a byte array of
  *                   length #ENTROPY_POOL_LENGTH.
  */
static void calculate_entropy_pool_checksum_internal(uint8_t *out, uint8_t *pool_state)
{
	uint32_t h[5];
    uint8_t hash[32];

    /*
     * RIPEMD-160 is used instead of SHA-256 because SHA-256 is already used
     * by getRandom256() to generate output values from the pool state.
     */
    ripemd_160_internal(pool_state, ENTROPY_POOL_LENGTH, h);

    write_hash_to_byte_array_internal(hash, h, true);

    TEE_MemMove((uint8_t*)out, (uint8_t*)hash, POOL_CHECKSUM_LENGTH);
}

/** Set (overwrite) the persistent entropy pool.
  * \param in_pool_state A byte array specifying the desired contents of the
  *                      persistent entropy pool. This must have a length
  *                      of #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't write to non-volatile
  *         memory) occurred.
  */
static TEE_Result set_entropy_pool(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	NonVolatileReturn nv_error;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint8_t checksum[POOL_CHECKSUM_LENGTH];

	/* Declare the write operation parameters */
	TEE_Param write_params[4];
	uint32_t write_param_types;
	TEE_Param write_params2[4];
	uint32_t write_param_types2;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> Input pool state;
	 * [IN]  params[0].memref.size   -> Size of the input pool state;
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * Write parameters:
	 * [IN]  params[0].memref.buffer -> Buffer with data to write in the storage.
	 * [IN]  params[0].memref.size   -> Size of the buffer to be wrote.
	 * [IN]  params[1].value.a       -> Starting address of the writing.
	 * [OUT] params[1].value.b       -> NonVolatileReturn error.
	 */
	write_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	write_param_types2 = write_param_types;

	/* Check the received parameter types */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Define the write operation parameters */
	write_params[0].memref.buffer =  (uint8_t *)(params[0].memref.buffer);
	write_params[0].memref.size =  (size_t)ENTROPY_POOL_LENGTH;
	write_params[1].value.a = (uint32_t)ADDRESS_ENTROPY_POOL;

	/* Write the current wallet (unencrypted section )in the wallet storage */
	result = write_cache_wallet_storage(session_data,
										write_param_types,
										write_params);

	nv_error = (NonVolatileReturn)(write_params[1].value.b);

	if (result != TEE_SUCCESS || nv_error != NV_NO_ERROR)
	{
		#ifdef OP_TEE_TA
		DMSG("Write wallet storage failed: 0x%x", result);
		#endif
		goto cleanup1;
	}

    calculate_entropy_pool_checksum_internal(checksum, (uint8_t *)(params[0].memref.buffer));

    write_params2[0].memref.buffer =  (uint8_t *)checksum;
	write_params2[0].memref.size =  (size_t)POOL_CHECKSUM_LENGTH;
	write_params2[1].value.a = (uint32_t)ADDRESS_POOL_CHECKSUM;

	/* Write the current wallet (unencrypted section )in the wallet storage */
	result = write_cache_wallet_storage(session_data,
										write_param_types2,
										write_params2);

	nv_error = (NonVolatileReturn)(write_params2[1].value.b);

	if (result != TEE_SUCCESS || nv_error != NV_NO_ERROR)
	{
		#ifdef OP_TEE_TA
		DMSG("Write wallet storage failed: 0x%x", result);
		#endif
		goto cleanup1;
	}

	result = flush_wallet_storage_internal(session_data, &nv_error);

	if (result != TEE_SUCCESS || nv_error != NV_NO_ERROR)
	{
		#ifdef OP_TEE_TA
		DMSG("Flush wallet storage failed: 0x%x", result);
		#endif
		goto cleanup1;
	}

    cleanup1:
    	return result; /* Success */
}

/** Obtain the contents of the persistent entropy pool.
  * \param out_pool_state A byte array specifying where the contents of the
  *                       persistent entropy pool should be placed. This must
  *                       have space for #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't read from
  *         non-volatile memory, or invalid checksum) occurred.
  */
static TEE_Result get_entropy_pool(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result result = TEE_SUCCESS;
    uint32_t exp_param_types;
    uint8_t checksum_calculated[POOL_CHECKSUM_LENGTH];
    uint8_t checksum_read[POOL_CHECKSUM_LENGTH];

    /* Declare read operation parameters */
    TEE_Param read_params[4];
    uint32_t read_param_types;
    TEE_Param read_params2[4];
    uint32_t read_param_types2;

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Entropy pool read.
     * [OUT] params[0].memref.size   -> Size of the entropy pool.
     */
    exp_param_types = TEE_PARAM_TYPES(
                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE);

    /*
     * Read parameters:
     * [OUT] params[0].memref.buffer -> Buffer to store the read data.
     * [OUT] params[0].memref.size   -> Size of the buffer.
     * [IN]  params[1].value.a       -> Starting address of the reading.
     * [OUT] params[1].value.b       -> Size actually read.
     */
    read_param_types = TEE_PARAM_TYPES(
                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                            TEE_PARAM_TYPE_VALUE_INOUT,
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE);

    read_param_types2 = read_param_types;

    /* Check the received parameter types */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Define the read operation parameters */
    read_params[0].memref.buffer = (uint8_t *)(params[0].memref.buffer);
    read_params[0].memref.size = (size_t)ENTROPY_POOL_LENGTH;
    read_params[1].value.a = (uint32_t)ADDRESS_ENTROPY_POOL;

    /* Fetch the data that is currently in the position to be write */
    result = read_cache_wallet_storage(session_data,
                                        read_param_types,
                                        read_params);

    if (result != TEE_SUCCESS)
    {
        #ifdef OP_TEE_TA
        DMSG("Read wallet storage failed : 0x%x", result);
        #endif
        goto cleanup1;
    }

    calculate_entropy_pool_checksum_internal(checksum_calculated, (uint8_t *)(params[0].memref.buffer));

    /* Define the read operation parameters */
    read_params2[0].memref.buffer = (uint8_t *)checksum_read;
    read_params2[0].memref.size = (size_t)POOL_CHECKSUM_LENGTH;
    read_params2[1].value.a = (uint32_t)ADDRESS_POOL_CHECKSUM;

    /* Fetch the data that is currently in the position to be write */
    result = read_cache_wallet_storage(session_data,
                                        read_param_types2,
                                        read_params2);

    if (result != TEE_SUCCESS)
    {
        #ifdef OP_TEE_TA
        DMSG("Read wallet storage failed : 0x%x", result);
        #endif
        goto cleanup1;
    }

    if (TEE_MemCompare((uint8_t*)checksum_read, (uint8_t*)checksum_calculated, (uint32_t)POOL_CHECKSUM_LENGTH) != 0)
        result = TEE_ERROR_BAD_STATE;

    cleanup1:
        return result;
}

/*==============================================================================
	WALLET FUNCTIONS
==============================================================================*/
/**
  * Computes wallet version of current wallet.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result update_wallet_version(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	/* This function does not expect any parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	/* Parameters unused */
	(void)&params;

	/* Some sanity checks */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
     * Hidden wallet should never ever have their version fields updated;
     * that would give away their presence.
     */
	if (session_data->is_hidden_wallet)
        return TEE_ERROR_BAD_STATE;

    if (session_data->is_encryption_key_non_zero)
        session_data->current_wallet->unencrypted.version = VERSION_IS_ENCRYPTED;
    else
        session_data->current_wallet->unencrypted.version = VERSION_UNENCRYPTED;

    return TEE_SUCCESS;
}

/**
  * Store contents of #current_wallet into non-volatile memory. This will also
  * call flush_wallet_storage_internal(), since that's usually what's wanted anyway.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result write_current_wallet_record(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	NonVolatileReturn nv_error;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/* Declare the write operation parameters */
	TEE_Param write_params[4];
	uint32_t write_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].value.a    -> Address to write the current wallet record.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * Write parameters:
	 * [IN]  params[0].memref.buffer -> Buffer with data to write in the storage.
	 * [IN]  params[0].memref.size   -> Size of the buffer to be wrote.
	 * [IN]  params[1].value.a       -> Starting address of the writing.
	 * [OUT] params[1].value.b       -> NonVolatileReturn error.
	 */
	write_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Check the received parameter types */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify if the storage was already opened */
	if(session_data->is_storage_open != true)
		return TEE_ERROR_BAD_STATE;

	/* Define the write operation parameters */
	write_params[0].memref.buffer =  (uint8_t *)&(session_data->current_wallet->unencrypted);
	write_params[0].memref.size =  sizeof(session_data->current_wallet->unencrypted);
	write_params[1].value.a = (uint32_t)(params[0].value.a + offsetof(WalletRecord, unencrypted) + GLOBAL_PARTITION_SIZE);

	/* Write the current wallet (unencrypted section )in the wallet storage */
	result = write_cache_wallet_storage(session_data,
										write_param_types,
										write_params);

	nv_error = (NonVolatileReturn)(write_params[1].value.b);

	if (result != TEE_SUCCESS || nv_error != NV_NO_ERROR)
	{
		#ifdef OP_TEE_TA
		DMSG("Write wallet storage failed: 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Write the current wallet (encrypted section )in the wallet storage */
	result = encrypted_write_wallet_storage_internal(
					session_data,
					(uint8_t *)&(session_data->current_wallet->encrypted),
					sizeof(session_data->current_wallet->encrypted),
					(uint32_t)(params[0].value.a + sizeof(session_data->current_wallet->unencrypted) + GLOBAL_PARTITION_SIZE),
					&nv_error);

	if (result != TEE_SUCCESS || nv_error != NV_NO_ERROR)
	{
		#ifdef OP_TEE_TA
		DMSG("Write wallet encrypted storage failed: 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Flush the write cache */
	result = flush_wallet_storage_internal(session_data, &nv_error);

	if (result != TEE_SUCCESS || nv_error != NV_NO_ERROR)
	{
		#ifdef OP_TEE_TA
		DMSG("Flush wallet storage failed: 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Resource cleanup */
	cleanup1:
		return result;
}

/**
  * Using the specified password and UUID (as the salt), derive an encryption
  * key and begin using it.
  *
  * This needs to be in wallet.c because there are situations (creating and
  * restoring a wallet) when the wallet UUID is not known before the beginning
  * of the appropriate function call.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result derive_and_set_encryption_key(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint8_t derived_key[SHA512_HASH_LENGTH];

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> UUID.
	 * [IN]  params[0].memref.size   -> Length of the UUID.
	 * [IN]  params[1].memref.buffer -> Password.
	 * [IN]  params[1].memref.size   -> Length of the password.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL)
	{
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* This should never happen */
    if (sizeof(derived_key) < WALLET_ENCRYPTION_KEY_LENGTH)
    {
    	/*
		 * Here the return could be return TEE_ERROR_BAD_STATE;
		 * but as this will NOT be treated as an error by the CA the most safest
		 * way is to set as TEE_ERROR_CANCEL to signal an operation that failed
		 * WHIT the needing to exit the program
		 */
    	return TEE_ERROR_CANCEL;
    }

    if (params[1].memref.size > 0)
    {
    	/* Create an key based on the password and on the UUID of the wallet */
        result = pbkdf2_internal(
        				session_data,
        				derived_key,
        				(uint8_t*)(params[1].memref.buffer),
        				params[1].memref.size,
        				(uint8_t*)(params[0].memref.buffer),
        				UUID_LENGTH);

        if (result != TEE_SUCCESS)
        {
        	#ifdef OP_TEE_TA
        	DMSG("Failed to perform pbkdf2 operation: 0x%x", result);
        	#endif
    		goto cleanup1;
        }

        /* Set the generated key */
        result = set_encryption_key_internal(session_data, derived_key);

        if (result != TEE_SUCCESS)
        {
        	#ifdef OP_TEE_TA
        	DMSG("Failed to set encryption key generated by pbkdf2: 0x%x", result);
        	#endif
    		goto cleanup1;
        }
    }
    else
    {
    	/* No password i.e. wallet is unencrypted. */
    	TEE_MemFill((uint8_t*)derived_key, 0, (uint32_t)sizeof(derived_key));

        result = set_encryption_key_internal(session_data, derived_key);

        if (result != TEE_SUCCESS)
        {
        	#ifdef OP_TEE_TA
        	DMSG("Failed to set encryption key generated by pbkdf2: 0x%x", result);
        	#endif
    		goto cleanup1;
        }
    }

    /* Resources cleanup */
    cleanup1:
    	return result;
}

/**
  * Get the current number of addresses in a wallet.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result get_number_addresses(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	WalletErrors wallet_error = WALLET_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint32_t num_addresses = 0;

	/*
	 * Expected:
	 * [OUT]  params[0].value.a  -> Number of addresses.
	 * [OUT]  params[0].value.b  -> Wallet last error.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!session_data->wallet_loaded)
	{
		/*
		 * Here the return should be return TEE_ERROR_ITEM_NOT_FOUND;
		 * but as this will be treated as an error by the CA the most safest way
		 * is to set as TEE_ERROR_BAD_STATE to signal an operation that failed
		 * but without the needing to exit the program
		 */
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_NOT_LOADED;
		goto cleanup1;
	}

	if (session_data->current_wallet->encrypted.num_addresses == 0)
	{
		/*
		 * Here the return should be return TEE_ERROR_NO_DATA;
		 * but as this will be treated as an error by the CA the most safest way
		 * is to set as TEE_ERROR_BAD_STATE to signal an operation that failed
		 * but without the needing to exit the program
		 */
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_EMPTY;
		goto cleanup1;
	}

	num_addresses = session_data->current_wallet->encrypted.num_addresses;

	/* Resource cleanup */
	cleanup1:
		params[0].value.a = num_addresses;
		params[0].value.b = (uint32_t)wallet_error;
		return result;
}

/**
  * Calculate the checksum (SHA-256 hash) of the current wallet's contents.
  * \param session_data A data pointer to a session context.  It is to be
  * used internally (only by the functions of the TA itself).
  * \param checksum The resulting SHA-256 hash will be written here. This must
  *                 be a byte array with space for #CHECKSUM_LENGTH bytes.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result calculate_wallet_checksum_internal(Session_data * session_data, uint8_t * checksum)
{
	TEE_Result result = TEE_SUCCESS;
	uint8_t * ptr;
	unsigned int i;
	uint32_t hash[8];

	/* Sanity check */
	if (checksum == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	sha256_init_internal(session_data);

	ptr = (uint8_t*)(session_data->current_wallet);

	/* Go trough every byte of the wallet record */
	for (i = 0; i < sizeof(WalletRecord); i++)
	{
		/* Skip the checksum field */
		if (i == offsetof(WalletRecord, encrypted.checksum))
			i += sizeof(session_data->current_wallet->encrypted.checksum);

		if (i < sizeof(WalletRecord))
			sha256_update_internal(session_data,
									&(ptr[i]),
									(uint32_t)sizeof(ptr[i]));
	}

	/* Finalize the hashing operation */
	result = sha256_final_internal(session_data, hash, (uint32_t)32);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do calculate_wallet_checksum operation : 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Convert the hash to an byte array */
	write_hash_to_byte_array_internal(checksum, hash, true);

	/* Resources cleanup */
	cleanup1:
		return result;
}

/**
  * Given an address handle, use the deterministic private key
  * generator to generate the private key associated with that address handle.
  * This function is only used by the TA itself.
  * \param session_data A data pointer to a session context.
  * \param out The private key will be written here (if everything goes well).
  *            This must be a byte array with space for 32 bytes.
  * \param ah The address handle to obtain the private key of.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
static WalletErrors get_private_key_internal(Session_data * session_data, uint8_t *out, AddressHandle ah)
{
	WalletErrors wallet_error;

	if (!(session_data->wallet_loaded))
    {
        wallet_error = WALLET_NOT_LOADED;
        return wallet_error;
    }

    if ((session_data->current_wallet->encrypted.num_addresses) == 0)
    {
        wallet_error = WALLET_EMPTY;
        return wallet_error;
    }

    if ((ah == 0)
    	|| (ah > (session_data->current_wallet->encrypted.num_addresses))
    	|| (ah == BAD_ADDRESS_HANDLE))
    {
        wallet_error = WALLET_INVALID_HANDLE;
        return wallet_error;
    }

    if (generate_deterministic256_internal(
    							session_data, out,
    							(session_data->current_wallet->encrypted.seed),
    							ah,
    							false,
    							NULL,
    							0))
    {
        /* This should never happen. */
        wallet_error = WALLET_RNG_FAILURE;
        return wallet_error;
    }

    wallet_error = WALLET_NO_ERROR;

    return wallet_error;
}

/**
  * Wrapper of get_private_key_internal() for a CA command. This function SHOULD
  * ONLY BE AVAILABLE FOR TESTING PURPOSES as all the function that need the
  * private key are developed inside the TA.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result get_private_key_test(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	WalletErrors wallet_error;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> The private key will be written here.
	 * [OUT] params[0].memref.size   -> Size of the key.
	 * [IN]  params[1].value.a   	 -> Address handle.
	 * [OUT] params[1].value.b   	 -> WalletErros return.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	wallet_error = get_private_key_internal(session_data, (uint8_t*)(params[0].memref.buffer), (AddressHandle)(params[1].value.a));

	if (wallet_error != WALLET_NO_ERROR)
		result = TEE_ERROR_BAD_STATE;

	params[1].value.b = (uint32_t)wallet_error;

	return result;
}

/**
  * Given an address handle, use the deterministic private key
  * generator to generate the address and public key associated
  * with that address handle.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  * \waning As the RIPEMD-160 is a digest function that is not specified by GP
  *         it is not available in the OP-TEE OS and as such this function lacks
  *         those functions in the end.
  */
static TEE_Result get_address_and_public_key(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	AddressHandle ah;
	WalletErrors wallet_error = WALLET_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint32_t hs[8];
	uint8_t buffer[32];
	uint8_t serialised_size;
	uint8_t serialised[ECDSA_MAX_SERIALISE_SIZE];

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer with the address hashed with
	 *									sha256.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [OUT] params[1].memref.buffer -> Buffer to write the public key.
	 * [OUT] params[1].memref.size   -> Size of the buffer.
	 * [IN]  params[2].value.a 		 -> Address handle.
	 * [OUT] params[2].value.b 		 -> WalletErrors return.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks on the parameters received */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(session_data->wallet_loaded))
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_NOT_LOADED;
		goto cleanup1;
	}

	if (session_data->current_wallet->encrypted.num_addresses == 0)
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_EMPTY;
		goto cleanup1;
	}

	ah = params[2].value.a;

	if ((ah == 0)
		|| (ah > session_data->current_wallet->encrypted.num_addresses)
		|| (ah == BAD_ADDRESS_HANDLE))
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_INVALID_HANDLE;
		goto cleanup1;
	}

	/* Calculate the private key */
	wallet_error = get_private_key_internal(session_data, buffer, ah);

	if (wallet_error != WALLET_NO_ERROR)
	{
		result = TEE_ERROR_BAD_STATE;
		goto cleanup1;
	}

	set_to_g_internal((PointAffine*)params[1].memref.buffer);

	point_multiply_internal(session_data,
							(PointAffine*)params[1].memref.buffer,
							buffer);

	serialised_size = ecdsa_serialise_internal(serialised,
											params[1].memref.buffer,
											true);

	if (serialised_size < 2)
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_INVALID_HANDLE;
		goto cleanup1;
	}

	sha256_init_internal(session_data);
	sha256_update_internal(session_data, serialised, (uint32_t)serialised_size);
	sha256_final_internal(session_data, hs, 32);

	write_hash_to_byte_array_internal(buffer, hs, true);

	ripemd_160_internal(buffer, 32, hs);

	write_hash_to_byte_array_internal(buffer, hs, true);

	TEE_MemMove((uint8_t*)(params[0].memref.buffer),
				(uint8_t*)buffer,
				(uint32_t)sizeof(buffer));

	/* Resources cleanup */
	cleanup1:
		params[2].value.b = (uint32_t)wallet_error;
		return result;
}

/**
  * Get the master public key of the currently loaded wallet. Every public key
  * (and address) in a wallet can be derived from the master public key and
  * chain code. However, even with possession of the master public key, all
  * private keys are still secret.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result get_master_public_key(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint8_t local_seed[SEED_LENGTH];
	BigNum256 k_par;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer to write the public key.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [OUT] params[1].memref.buffer -> Buffer to write the chain code.
	 * [OUT] params[1].memref.size   -> Size of the buffer.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks on the parameters received */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(session_data->wallet_loaded))
		return TEE_ERROR_BAD_STATE;

	TEE_MemMove((uint8_t*)local_seed,
				(uint8_t*)(session_data->current_wallet->encrypted.seed),
				(uint32_t)SEED_LENGTH);

	TEE_MemMove((uint8_t*)(params[1].memref.buffer),
				(uint8_t*)&(local_seed[32]),
				(uint32_t)32);

	k_par = (BigNum256)local_seed;

	swap_endian256_internal(k_par);	/* Since the seed is big-endian */

	set_field_to_n_internal(session_data);

	big_modulo_internal(session_data, k_par, k_par);	/* Just in case */

	set_to_g_internal((PointAffine*)(params[0].memref.buffer));

	point_multiply_internal(session_data,
							(PointAffine*)(params[0].memref.buffer),
							k_par);

	return result;
}

/**
  * Change the encryption key of a wallet.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result change_encryption_key(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	WalletErrors wallet_error = WALLET_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/* Declare deriveAndSetEncryptionKey operation parameters */
	TEE_Param dasec_params[4];
	uint32_t dasec_param_types;

	/* Declare updateWalletVerison operation parameters */
	uint32_t uwv_param_types;

	/* Declare writeCurrentWallet operation parameters */
	TEE_Param wcwr_params[4];
	uint32_t wcwr_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> Password.
	 * [IN]  params[0].memref.size   -> Length of the password.
	 * [OUT] params[1].value.a       -> Wallet last error.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * deriveAndSetEncryptionKey parameters:
	 * [IN]  params[0].memref.buffer -> UUID.
	 * [IN]  params[0].memref.size   -> Length of the UUID.
	 * [IN]  params[1].memref.buffer -> Password.
	 * [IN]  params[1].memref.size   -> Length of the password.
	 */
	dasec_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	uwv_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * writeCurrentWallet parameters:
	 * [IN]  params[0].value.a    -> Address to write the current wallet record.
	 */
	wcwr_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the wallet is loaded */
	if (!(session_data->wallet_loaded))
	{
		/*
		 * Here the return should be return TEE_ERROR_ITEM_NOT_FOUND;
		 * but as this will be treated as an error by the CA the most safest way
		 * is to set as TEE_ERROR_BAD_STATE to signal an operation that failed
		 * but without the needing to exit the program
		 */
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_NOT_LOADED;
		goto cleanup1;
	}

	/* Define deriveAndSetEncryptionKey parameters */
	dasec_params[0].memref.buffer = (uint8_t*)&(session_data->current_wallet->unencrypted.uuid);
    dasec_params[0].memref.size = (size_t)UUID_LENGTH;
    dasec_params[1].memref.buffer = (uint8_t*)(params[0].memref.buffer);
    dasec_params[1].memref.size = (size_t)(params[0].memref.size);

	result = derive_and_set_encryption_key(session_data,
										dasec_param_types,
										dasec_params);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do derive_and_set_encryption_key operation : 0x%x", result);
		#endif

		/*
		 * Here we needed an wallet_error because otherwise even if the operation
		 * failed it would say that there wasn't any error (because the default
		 * value is WALLET_NO_ERROR) so the value chosen was invalid operation
		 */
		wallet_error = WALLET_INVALID_OPERATION;
		goto cleanup1;
	}

	/* Updating the version field for a hidden wallet would reveal where it is, do don't do it */
	if (!(session_data->is_hidden_wallet))
	{
		result = update_wallet_version(session_data, uwv_param_types, NULL);

		if(result != TEE_SUCCESS)
		{
			#ifdef OP_TEE_TA
			DMSG("Failed to do update_wallet_version operation : 0x%x", result);
			#endif

			/*
			 * Here we are assuming that only reason that the update_wallet_version_
			 * could fail is because the parameters were invalid (as the other
			 * reason is already checked in the first if) but those were set here
			 * so this situation should never occur and as such the wallet_error
			 * value does matter that much here so we will leave it as an invalid
			 * operation
			 */
			wallet_error = WALLET_INVALID_OPERATION;
			goto cleanup1;
		}
	}

	/* Calculate the wallet checksum */
	result = calculate_wallet_checksum_internal(
							session_data,
							session_data->current_wallet->encrypted.checksum);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do calculate_wallet_checksum_internal operation : 0x%x", result);
		#endif

		/*
		 * Here we needed an wallet_error because otherwise even if the operation
		 * failed it would say that there wasn't any error (because the default
		 * value is WALLET_NO_ERROR) so the value chosen was invalid operation
		 */
		wallet_error = WALLET_INVALID_OPERATION;
		goto cleanup1;
	}

	/* Write the current wallet record into the storage */
	wcwr_params[0].value.a = session_data->wallet_nv_address;

	result = write_current_wallet_record(session_data,
										wcwr_param_types,
										wcwr_params);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do write_current_wallet_record operation : 0x%x", result);
		#endif
		wallet_error = WALLET_WRITE_ERROR;
		goto cleanup1;
	}

	/* Resources cleanup */
	cleanup1:
		params[1].value.a = (uint32_t)wallet_error;
		return result;
}

/**
  * Load contents of non-volatile memory into a #WalletRecord structure. This
  * doesn't care if there is or isn't actually a wallet at the specified
  * address.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result read_wallet_record(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	WalletRecord * wallet_record;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint32_t unencrypted_size;
    uint32_t encrypted_size;

    /* Declare read operation parameters */
	TEE_Param read_params[4];
	uint32_t read_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Structure to write the wallet record read.
	 * [OUT] params[0].memref.size   -> Size of the wallet record to be read.
	 * [IN]  params[1].value.a       -> Address to read the wallet record from.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * Read parameters:
	 * [OUT] params[0].memref.buffer -> Buffer to store the read data.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [IN]  params[1].value.a       -> Starting address of the reading.
	 * [OUT] params[1].value.b       -> Size actually read.
	 */
	read_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Check the received parameter types and the pointer of the first parameter */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if(session_data->is_storage_open != true)
		return TEE_ERROR_BAD_STATE;

	wallet_record = (WalletRecord *)(params[0].memref.buffer);

    unencrypted_size = sizeof(wallet_record->unencrypted);
    encrypted_size = sizeof(wallet_record->encrypted);

    /*
     * Before doing any reading, do some sanity checks. These ensure that the
     * size of the unencrypted and encrypted portions are an integer multiple of
     * the AES block size
     */
    if (((unencrypted_size % 16) != 0) || ((encrypted_size % 16) != 0))
    {
    	/*
    	 * Here the return should be return TEE_ERROR_BAD_STATE; but to
    	 * differentiate the WalletError return the return is different
    	 */
    	return TEE_ERROR_BAD_FORMAT;
    }

    /* Define the read operation parameters */
	read_params[0].memref.buffer = (uint8_t *)&(wallet_record->unencrypted);
	read_params[0].memref.size =  (size_t)unencrypted_size;
	read_params[1].value.a = (uint32_t)(params[1].value.a + offsetof(WalletRecord, unencrypted) + (uint32_t)GLOBAL_PARTITION_SIZE);

	/* Read the wallet record (unencrypted section) */
	result = read_cache_wallet_storage(session_data, read_param_types, read_params);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Read wallet storage failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	/* Read the wallet record (encrypted section) */
	result = encrypted_read_wallet_storage_internal(
					session_data,
					(uint8_t *)&(wallet_record->encrypted),
					encrypted_size,
					(uint32_t)(params[1].value.a + offsetof(WalletRecord, encrypted) + (uint32_t)GLOBAL_PARTITION_SIZE));

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Read wallet encrypted storage failed : 0x%x", result);
		#endif
		goto cleanup1;
	}

	cleanup1:
		return result;
}

/**
  * Initialise a wallet (load it if it's there).
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result init_wallet(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	WalletErrors wallet_error = WALLET_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint8_t hash[CHECKSUM_LENGTH];
	uint8_t uuid[UUID_LENGTH];

	/* Declare parameters that will be used in read operations */
	TEE_Param read_params[4];
	uint32_t read_param_types;

	/* Declare deriveAndSetEncryptionKey operation parameters */
	TEE_Param dasec_params[4];
	uint32_t dasec_param_types;

	/* Declare readWalletRecord operation parameters */
	TEE_Param rwr_params[4];
	uint32_t rwr_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> Password.
	 * [IN]  params[0].memref.size   -> Length of the password.
	 * [IN]  params[1].value.a       -> Wallet specification number.
	 * [OUT] params[1].value.b       -> Wallet last error.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * Read parameters:
	 * [OUT] params[0].memref.buffer -> Buffer to store the read data.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [IN]  params[1].value.a       -> Starting address of the reading.
	 * [OUT] params[1].value.b       -> Size actually read.
	 */
	read_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_MEMREF_OUTPUT,
									TEE_PARAM_TYPE_VALUE_INOUT,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	/*
	 * deriveAndSetEncryptionKey parameters:
	 * [IN]  params[0].memref.buffer -> UUID.
	 * [IN]  params[0].memref.size   -> Length of the UUID.
	 * [IN]  params[1].memref.buffer -> Password.
	 * [IN]  params[1].memref.size   -> Length of the password.
	 */
	dasec_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * readWalletRecord parameters:
	 * [OUT] params[0].memref.buffer -> Structure to write the wallet record read.
	 * [OUT] params[0].memref.size   -> Size of the wallet record to be read.
	 * [IN]  params[1].value.a       -> Address to read the wallet record from.
	 */
	rwr_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (exp_param_types != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	session_data->wallet_nv_address = (params[1].value.a) * sizeof(WalletRecord);

	/* Define the read operation parameters */
	read_params[0].memref.buffer = (uint8_t*)uuid;
	read_params[0].memref.size = (size_t)UUID_LENGTH;
	read_params[1].value.a = (uint32_t)((session_data->wallet_nv_address) + offsetof(WalletRecord, unencrypted.uuid) + (uint32_t)GLOBAL_PARTITION_SIZE);

	result = read_cache_wallet_storage(session_data,
										read_param_types,
										read_params);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to read from the cache: 0x%x", result);
		#endif
		wallet_error = WALLET_READ_ERROR;
		goto cleanup1;
	}

	/* Define deriveAndSetEncryptionKey parameters */
	dasec_params[0].memref.buffer = (uint8_t*)uuid;
    dasec_params[0].memref.size = (size_t)UUID_LENGTH;
    dasec_params[1].memref.buffer = (uint8_t*)(params[0].memref.buffer);
    dasec_params[1].memref.size = (size_t)(params[0].memref.size);

	result = derive_and_set_encryption_key(session_data,
											dasec_param_types,
											dasec_params);

	if (result != TEE_SUCCESS)
	{
		/* Here should be an generic error but as it is not available ... */
		#ifdef OP_TEE_TA
		DMSG("Failed to derive_and_set_encryption_key : 0x%x", result);
		#endif
		wallet_error = WALLET_INVALID_OPERATION;
		goto cleanup1;
	}

	/* Define readWalletRecord parameters */
	rwr_params[0].memref.buffer = (WalletRecord*)(session_data->current_wallet);
	rwr_params[0].memref.size = sizeof(WalletRecord);
	rwr_params[1].value.a = session_data->wallet_nv_address;

	result = read_wallet_record(session_data, rwr_param_types, rwr_params);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to read wallet record: 0x%x", result);
		#endif

		if (result == TEE_ERROR_BAD_FORMAT)
        	wallet_error = WALLET_INVALID_OPERATION;
        else if (result == TEE_ERROR_BAD_STATE)
            wallet_error = WALLET_READ_ERROR;

        goto cleanup1;
	}

	if (session_data->current_wallet->unencrypted.version == VERSION_NOTHING_THERE)
		session_data->is_hidden_wallet = true;
	else
	{
		if ((session_data->current_wallet->unencrypted.version == VERSION_UNENCRYPTED)
			|| (session_data->current_wallet->unencrypted.version == VERSION_IS_ENCRYPTED))
			session_data->is_hidden_wallet = false;
		else
		{
			result = TEE_ERROR_BAD_STATE;
			wallet_error = WALLET_NOT_THERE;
			goto cleanup1;
		}
	}

	/* Calculate the wallet checksum and check if it matches */
	result = calculate_wallet_checksum_internal(session_data, hash);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to calculate_wallet_checksum: 0x%x", result);
		#endif
		/* Here should be an generic error but as it is not available ... */
		wallet_error = WALLET_INVALID_OPERATION;
		goto cleanup1;
	}

	if (big_compare_variable_size_internal(
						session_data->current_wallet->encrypted.checksum,
						hash,
						CHECKSUM_LENGTH) != BIGCMP_EQUAL)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to compare checksums");
		#endif
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_NOT_THERE;
		goto cleanup1;
	}

	session_data->wallet_loaded = true;

	/* Not really needed but ... */
	wallet_error = WALLET_NO_ERROR;

	/* Resource cleanup */
	cleanup1:
		params[1].value.b = (uint32_t)wallet_error;
		return result;
}

/**
  * Unload wallet, so that it cannot be used until init_wallet() is called.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result uninit_wallet(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)&params;

	clear_parent_public_key_cache_internal(session_data);

	session_data->wallet_loaded = false;
	session_data->is_hidden_wallet = false;
	session_data->wallet_nv_address = 0;

	TEE_MemFill((WalletRecord*)(session_data->current_wallet),
				0,
				(uint32_t)sizeof(WalletRecord));

	return result;
}

/**
  * Obtain publicly available information about a wallet. "Publicly available"
  * means that the leakage of that information would have a relatively low
  * impact on security (compared to the leaking of, say, the deterministic
  * private key generator seed).
  *
  * Note that unlike most of the other wallet functions, this function does
  * not require the wallet to be loaded. This is so that a user can be
  * presented with a list of all the wallets stored on a hardware Bitcoin
  * wallet, without having to know the encryption key to each wallet.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result get_wallet_info(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint32_t local_wallet_nv_address;
	WalletRecord local_wallet_record;

	/* Declare readWalletRecord operation parameters */
	TEE_Param rwr_params[4];
	uint32_t rwr_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].value.a       -> Version.
	 * [IN]  params[0].value.b       -> Wallet number specification.
	 * [OUT] params[1].memref.buffer -> Name.
	 * [OUT] params[1].memref.size   -> Size of Name.
	 * [OUT] params[2].memref.buffer -> UUID.
	 * [OUT] params[2].memref.size   -> Size of UUID.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE);

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Structure to write the wallet record read.
	 * [OUT] params[0].memref.size   -> Size of the wallet record to be read.
	 * [IN]  params[1].value.a       -> Address to read the wallet record from.
	 */
	rwr_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity check on the parameters received */
	if (param_types != exp_param_types
	 || params[1].memref.buffer == NULL
	 || params[2].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	local_wallet_nv_address = (uint32_t)(params[0].value.b) * sizeof(WalletRecord);

	/* Define readWalletRecord parameters */
	rwr_params[0].memref.buffer = (WalletRecord*)&local_wallet_record;
	rwr_params[0].memref.size = sizeof(WalletRecord);
	rwr_params[1].value.a = local_wallet_nv_address;

	result = read_wallet_record(session_data, rwr_param_types, rwr_params);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to read_wallet_record : 0x%x", result);
		#endif
        goto cleanup1;
	}

	/* Copy the version of the wallet */
	params[0].value.a = (uint32_t)local_wallet_record.unencrypted.version;

	TEE_MemMove(
		(uint8_t*)params[1].memref.buffer,
		(uint8_t*)local_wallet_record.unencrypted.name,
		(uint32_t)(params[1].memref.size));

	TEE_MemMove(
		(uint8_t*)params[2].memref.buffer,
		(uint8_t*)local_wallet_record.unencrypted.uuid,
		(uint32_t)(params[2].memref.size));

	/* Resource cleanup */
	cleanup1:
		return result;
}

/** Change the name of the currently loaded wallet.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result change_wallet_name(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	WalletErrors wallet_error = WALLET_NO_ERROR;

	/* Declare writeCurrentWallet operation parameters */
	TEE_Param wcwr_params[4];
	uint32_t wcwr_param_types;

	/*
	 * Expected:
	 * [IN]  params[0].memref.buffer -> New name
	 * [IN]  params[0].memref.size   -> Size of New name.
	 * [OUT] params[1].value.a       -> WalletError;
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_VALUE_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * writeCurrentWallet parameters:
	 * [IN]  params[0].value.a    -> Address to write the current wallet record.
	 */
	wcwr_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity check on the parameters received */
	if (param_types != exp_param_types || params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(session_data->wallet_loaded))
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_NOT_LOADED;
	}

	if (session_data->is_hidden_wallet)
	{
		/*
         * Wallet name updates on a hidden wallet would reveal where it is
         * (since names are publicly visible), so don't allow name changes.
         */
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_INVALID_OPERATION;
	}

	TEE_MemMove(
		(uint8_t*)&(session_data->current_wallet->unencrypted.name),
		(uint8_t*)(params[0].memref.buffer),
		(uint32_t)(params[0].memref.size));

	calculate_wallet_checksum_internal(
		session_data,
		session_data->current_wallet->encrypted.checksum);

	/* Write the current wallet record into the storage */
	wcwr_params[0].value.a = session_data->wallet_nv_address;

	result = write_current_wallet_record(session_data,
										wcwr_param_types,
										wcwr_params);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do write_current_wallet_record operation : 0x%x", result);
		#endif
		wallet_error = WALLET_WRITE_ERROR;
		goto cleanup1;
	}

	/* Resources cleanup */
	cleanup1:
		params[1].value.a = (uint32_t)wallet_error;
		return result;
}

/**
  * Create new wallet. A brand new wallet contains no addresses and should
  * have a unique, unpredictable deterministic private key generation seed.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  * \warning This will erase the current one.
  */
static TEE_Result new_wallet(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;
	uint8_t uuid[UUID_LENGTH];
	newWalletHelper * aux_params;
	WalletErrors wallet_error = WALLET_NO_ERROR;

	/* Declare readWalletRecord operation parameters */
	TEE_Param rwr_params[4];
	uint32_t rwr_param_types;

	/* Declare deriveAndSetEncryptionKey operation parameters */
	TEE_Param dasec_params[4];
	uint32_t dasec_param_types;

	/* Declare updateWalletVerison operation parameters */
	uint32_t uwv_param_types;

	/* Declare writeCurrentWallet operation parameters */
	TEE_Param wcwr_params[4];
	uint32_t wcwr_param_types;

	/* Declare initWallet operation parameters */
	TEE_Param iw_params[4];
	uint32_t iw_param_types;

	/*
     * Expected:
     * [IN]  params[0].memref.buffer -> Name
     * [IN]  params[0].memref.size   -> Size of Name.
     * [IN]  params[1].memref.buffer -> Seed
     * [IN]  params[1].memref.size   -> Size of Seed.
     * [IN]  params[2].memref.buffer -> Password
     * [IN]  params[2].memref.size   -> Size of Password.
     * [IO]  params[3].memref.buffer -> newWalletHelper;
     * [IN]  params[3].memref.size   -> Size of newWalletHelper.
     */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INOUT);

	/*
	 * readWalletRecord parameters:
	 * [OUT] params[0].memref.buffer -> Structure to write the wallet record read.
	 * [OUT] params[0].memref.size   -> Size of the wallet record to be read.
	 * [IN]  params[1].value.a       -> Address to read the wallet record from.
	 */
	rwr_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * deriveAndSetEncryptionKey parameters:
	 * [IN]  params[0].memref.buffer -> UUID.
	 * [IN]  params[0].memref.size   -> Length of the UUID.
	 * [IN]  params[1].memref.buffer -> Password.
	 * [IN]  params[1].memref.size   -> Length of the password.
	 */
	dasec_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* UpdateWalletVersion parameters */
	uwv_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * writeCurrentWallet parameters:
	 * [IN]  params[0].value.a    -> Address to write the current wallet record.
	 */
	wcwr_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
     * initWallet parameters:
     * [IN]  params[0].memref.buffer -> Password.
     * [IN]  params[0].memref.size   -> Length of the password.
     * [IN]  params[1].value.a       -> Wallet specification number.
     * [OUT] params[1].value.b       -> Wallet last error.
     */
    iw_param_types = TEE_PARAM_TYPES(
                            TEE_PARAM_TYPE_MEMREF_INPUT,
                            TEE_PARAM_TYPE_VALUE_INOUT,
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE);

    /* Sanity check on the parameters passed */
	if (exp_param_types != param_types
	 || params[0].memref.buffer == NULL
	 || params[3].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	aux_params = (newWalletHelper*)(params[3].memref.buffer);

	/* Set the address of the wallet */
	session_data->wallet_nv_address =  (aux_params->wallet_spec) * sizeof(WalletRecord);

	/* Check for existing wallet */
	rwr_params[0].memref.buffer = (WalletRecord*)(session_data->current_wallet);
	rwr_params[0].memref.size = sizeof(WalletRecord);
	rwr_params[1].value.a = session_data->wallet_nv_address;

	result = read_wallet_record(session_data, rwr_param_types, rwr_params);

	if (result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to read wallet record: 0x%x", result);
		#endif

		if (result == TEE_ERROR_BAD_FORMAT)
        	wallet_error = WALLET_INVALID_OPERATION;
        else if (result == TEE_ERROR_BAD_STATE)
            wallet_error = WALLET_READ_ERROR;

        goto cleanup1;
	}

	if (session_data->current_wallet->unencrypted.version != VERSION_NOTHING_THERE)
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_ALREADY_EXISTS;
		goto cleanup1;
	}

	if (aux_params->make_hidden)
	{
		/*
         * The creation of a hidden wallet is supposed to be discreet, so
         * all unencrypted fields should be left untouched. This forces us
         * to use the existing UUID.
         */
		TEE_MemMove(
			(uint8_t*)uuid,
			(uint8_t*)(session_data->current_wallet->unencrypted.uuid),
			(uint32_t)UUID_LENGTH);
	}
	else
	{
		/*
         * Generate wallet UUID now, because it is needed to derive the
         * wallet encryption key.
         */
		TEE_MemMove(
			(uint8_t*)uuid,
			(uint8_t*)(aux_params->random_buffer_0),
			(uint32_t)UUID_LENGTH);
	}

	/* Define deriveAndSetEncryptionKey parameters */
	dasec_params[0].memref.buffer = (uint8_t*)uuid;
    dasec_params[0].memref.size = (size_t)UUID_LENGTH;
    dasec_params[1].memref.buffer = (uint8_t*)(params[2].memref.buffer);
    dasec_params[1].memref.size = (size_t)(params[2].memref.size);

	result = derive_and_set_encryption_key(
					session_data,
					dasec_param_types,
					dasec_params);

	if (result != TEE_SUCCESS)
	{
		/* Here should be an generic error but as it is not available ... */
		#ifdef OP_TEE_TA
		DMSG("Failed to derive_and_set_encryption_key: 0x%x", result);
		#endif
		wallet_error = WALLET_INVALID_OPERATION;
		goto cleanup1;
	}

	/* Update unencrypted fields of current_wallet */
	if (!(aux_params->make_hidden))
	{
		result = update_wallet_version(session_data, uwv_param_types, NULL);

		if(result != TEE_SUCCESS)
		{
			#ifdef OP_TEE_TA
			DMSG("Failed to do update_wallet_version operation: 0x%x", result);
			#endif

			/*
			 * Here we are assuming that only reason that the update_wallet_version_
			 * could fail is because the parameters were invalid (as the other
			 * reason is already checked in the first if) but those were set here
			 * so this situation should never occur and as such the wallet_error
			 * value does matter that much here so we will leave it as an invalid
			 * operation
			 */
			wallet_error = WALLET_INVALID_OPERATION;
			goto cleanup1;
		}

		TEE_MemFill(
			session_data->current_wallet->unencrypted.reserved,
			0,
			sizeof(session_data->current_wallet->unencrypted.reserved));

		TEE_MemMove(
			(uint8_t*)(session_data->current_wallet->unencrypted.name),
			(uint8_t*)(params[0].memref.buffer),
			(uint32_t)(params[0].memref.size));

		TEE_MemMove(
			(uint8_t*)(session_data->current_wallet->unencrypted.uuid),
			(uint8_t*)uuid,
			(uint32_t)UUID_LENGTH);
	}

	/* Update encrypted fields of current_wallet */
	session_data->current_wallet->encrypted.num_addresses = 0;

	TEE_MemMove(
		(uint8_t*)(session_data->current_wallet->encrypted.padding),
		(uint8_t*)(aux_params->random_buffer_1),
		sizeof(session_data->current_wallet->encrypted.padding));

	TEE_MemFill(
		session_data->current_wallet->encrypted.reserved,
		0,
		sizeof(session_data->current_wallet->encrypted.reserved));

	if (aux_params->use_seed)
	{
		TEE_MemMove(
			(uint8_t*)(session_data->current_wallet->encrypted.seed),
			(uint8_t*)(params[1].memref.buffer),
			(uint32_t)(params[1].memref.size));
	}
	else
	{
		TEE_MemMove(
			(uint8_t*)(session_data->current_wallet->encrypted.seed),
			(uint8_t*)(aux_params->random_buffer_2),
			(uint32_t)32);

		TEE_MemMove(
			(uint8_t*)&((session_data->current_wallet->encrypted.seed)[32]),
			(uint8_t*)(aux_params->random_buffer_3),
			(uint32_t)32);
	}

	/* Calculate the wallet checksum */
	result = calculate_wallet_checksum_internal(
						session_data,
						session_data->current_wallet->encrypted.checksum);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do calculate_wallet_checksum_internal operation: 0x%x", result);
		#endif

		/*
		 * Here we needed an wallet_error because otherwise even if the operation
		 * failed it would say that there wasn't any error (because the default
		 * value is WALLET_NO_ERROR) so the value chosen was invalid operation
		 */
		wallet_error = WALLET_INVALID_OPERATION;
		goto cleanup1;
	}

	/* Write the current wallet record into the storage */
	wcwr_params[0].value.a = session_data->wallet_nv_address;

	result = write_current_wallet_record(
					session_data,
					wcwr_param_types,
					wcwr_params);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do write_current_wallet_record operation: 0x%x", result);
		#endif
		wallet_error = WALLET_WRITE_ERROR;
		goto cleanup1;
	}

	/* Initialize  the wallet */
	iw_params[0].memref.buffer = (uint8_t*)(params[2].memref.buffer);
    iw_params[0].memref.size = (size_t)(params[2].memref.size);
    iw_params[1].value.a = aux_params->wallet_spec;

    result = init_wallet(session_data, iw_param_types, iw_params);

    if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do init_wallet operation : 0x%x", result);
		#endif
		wallet_error = (WalletErrors)(iw_params[1].value.b);
		goto cleanup1;
	}

	/* Resources cleanup */
	cleanup1:
		//((newWalletHelper*)(params[3].memref.buffer))->wallet_error = wallet_error;
		aux_params->wallet_error = wallet_error;
		return result;
}

/**
  * Allows the CA to get the seed encrypted or not.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  * \warning This will erase the current one.
  */
static TEE_Result get_seed(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	WalletErrors wallet_error = WALLET_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/*
     * Expected:
     * [IN]  params[0].value.a       -> Boolean to indicate if is to encrypt or
     * 									not the seed.
     * [OUT] params[0].value.b       -> WalletErrors return (of wallet_loaded).
     * [OUT] params[1].memref.buffer -> Buffer to write the seed.
     * [OUT] params[1].memref.size   -> Size of the buffer.
     */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/* Sanity check on the parameters received */
	if (exp_param_types != param_types || params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(session_data->wallet_loaded))
	{
		wallet_error = WALLET_NOT_LOADED;
		result = TEE_ERROR_BAD_STATE;
		goto cleanup1;
	}

	/* Check if the seed it to encrypt */
	if ((bool)(params[0].value.a))
	{
		/* Encrypt the data to be written */
		result = aes_xts_internal(
						session_data,
						TEE_MODE_ENCRYPT,
						(uint8_t*)(session_data->current_wallet->encrypted.seed),
						(uint32_t)(params[1].memref.size), /* OR SEED_LENGTH */
						(uint8_t*)(params[1].memref.buffer),
						(uint32_t)(params[1].memref.size));

		if (result != TEE_SUCCESS)
		{
			#ifdef OP_TEE_TA
			DMSG("AES XTS Encrypt failed : 0x%x", result);
			#endif
			goto cleanup1;
		}
	}
	else
	{
		TEE_MemMove(
			(uint8_t*)(params[1].memref.buffer),
			(uint8_t*)(session_data->current_wallet->encrypted.seed),
			(uint32_t)(params[1].memref.size));
	}

	/* Resources cleanup */
	cleanup1:
		params[0].value.b = (uint32_t)wallet_error;
		return result;
}

/** Generate a new address using the deterministic private key generator.
  * \param session_data A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in
  */
static TEE_Result make_new_address(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	AddressHandle ah_return = BAD_ADDRESS_HANDLE;
	WalletErrors wallet_error = WALLET_NO_ERROR;
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types;

	/* Declare writeCurrentWallet operation parameters */
	TEE_Param wcwr_params[4];
	uint32_t wcwr_param_types;

	TEE_Param gaapk_params[4];
	uint32_t gaapk_param_types;

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer to write the address.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [OUT] params[1].memref.buffer -> Buffer to write the public key.
	 * [OUT] params[1].memref.size   -> Size of the buffer.
	 * [OUT] params[2].value.a 		 -> AddressHandle return.
	 * [OUT] params[2].value.b 		 -> WalletErros return.
	 */
	exp_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_OUTPUT,
							TEE_PARAM_TYPE_NONE);

	/*
	 * writeCurrentWallet parameters:
	 * [IN]  params[0].value.a    -> Address to write the current wallet record.
	 */
	wcwr_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);

	/*
	 * Expected:
	 * [OUT] params[0].memref.buffer -> Buffer with the address hashed with sha256.
	 * [OUT] params[0].memref.size   -> Size of the buffer.
	 * [OUT] params[1].memref.buffer -> Buffer to write the public key.
	 * [OUT] params[1].memref.size   -> Size of the buffer.
	 * [IN]  params[2].value.a 		 -> Address handle.
	 * [OUT] params[2].value.b 		 -> WalletErrors return.
	 */
	gaapk_param_types = TEE_PARAM_TYPES(
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_VALUE_INOUT,
							TEE_PARAM_TYPE_NONE);

	/* Some sanity checks */
	if (param_types != exp_param_types
		|| params[0].memref.buffer == NULL
		|| params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(session_data->wallet_loaded))
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_NOT_LOADED;
		goto cleanup1;
	}

	if (session_data->current_wallet->encrypted.num_addresses >= MAX_ADDRESSES)
	{
		result = TEE_ERROR_BAD_STATE;
		wallet_error = WALLET_FULL;
		goto cleanup1;
	}

	(session_data->current_wallet->encrypted.num_addresses)++;

	/* Calculate the wallet checksum */
	result = calculate_wallet_checksum_internal(
							session_data,
							session_data->current_wallet->encrypted.checksum);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do calculate_wallet_checksum_internal operation : 0x%x", result);
		#endif

		/*
		 * Just to guarantee that the result is different than
		 * TEE_ERROR_BAD_STRATE
		 */
		result = TEE_ERROR_CANCEL;

		/*
		 * Here we needed an wallet_error because otherwise even if the operation
		 * failed it would say that there wasn't any error (because the default
		 * value is WALLET_NO_ERROR) so the value chosen was invalid operation
		 */
		wallet_error = WALLET_INVALID_OPERATION;
		goto cleanup1;
	}

	/* Write the current wallet record into the storage */
	wcwr_params[0].value.a = session_data->wallet_nv_address;

	result = write_current_wallet_record(session_data,
										wcwr_param_types,
										wcwr_params);

	if(result != TEE_SUCCESS)
	{
		#ifdef OP_TEE_TA
		DMSG("Failed to do write_current_wallet_record operation : 0x%x", result);
		#endif
		wallet_error = WALLET_WRITE_ERROR;
		goto cleanup1;
	}

	/* Define the parameters for the getAddressAndPublicKey function */
	gaapk_params[0].memref.buffer = (uint8_t*)(params[0].memref.buffer);
	gaapk_params[0].memref.size = params[0].memref.size;
	gaapk_params[1].memref.buffer = (PointAffine*)(params[1].memref.buffer);
	gaapk_params[1].memref.size = params[1].memref.size;
	gaapk_params[2].value.a = (uint32_t)(session_data->current_wallet->encrypted.num_addresses);

	result = get_address_and_public_key(session_data,
										gaapk_param_types,
										gaapk_params);

	wallet_error = (WalletErrors)(gaapk_params[2].value.b);

	if (wallet_error != WALLET_NO_ERROR)
		ah_return = BAD_ADDRESS_HANDLE;
	else
		ah_return = session_data->current_wallet->encrypted.num_addresses;

	/* Resources cleanup */
	cleanup1:
		params[2].value.a = (uint32_t)ah_return;
		params[2].value.b = (uint32_t)wallet_error;
		return result;
}

/*==============================================================================
	MISCELLANEOUS FUNCTIONS
==============================================================================*/
/**
  * This is a test function used to measure the time of a TA function call.
  * \param sess_ctx A data pointer to a session context.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2
  *         published by GlobalPlatform.
  */
static TEE_Result test_function(Session_data * session_data, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_NONE);
	/* Unused parameters */
	(void)&session_data;
	(void)&params;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return result;
}

/*==============================================================================
	INVOKE COMMAND ENTRY POINT
==============================================================================*/
/**
  * Called when a TA is invoked. sess_ctx hold that value that was
  * assigned by TA_OpenSessionEntryPoint(). The rest of the parameters
  * comes from normal world.
  * \param sess_ctx A data pointer to a session context.
  * \param cmd_id A Trusted Application-specific code that identifies the
  *               command to be invoked.
  * \param param_types The types of the four parameters.
  * \param params A pointer to an array of four parameters.
  * \return TEE_ERROR_BAD_PARAMETERS when the parameters send are not correct.
  *         Or returns the function invoked return.
  */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id)
	{
		case CMD_INITIALIZE_HANDLERS:
			return initialize_handlers((Session_data *)sess_ctx, param_types, params);

		case CMD_FINALIZE_HANDLERS:
			return finalize_handlers((Session_data *)sess_ctx, param_types, params);

		case CMD_CREATE_WALLET_STORAGE:
			return create_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_OPEN_WALLET_STORAGE:
			return open_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_CLOSE_WALLET_STORAGE:
			return close_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_DELETE_WALLET_STORAGE:
			return delete_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_SEEK_WALLET_STORAGE:
			return seek_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_WRITE1_WALLET_STORAGE:
			return write1_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_READ1_WALLET_STORAGE:
			return read1_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_WRITE_WALLET_STORAGE:
			return write_cache_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_READ_WALLET_STORAGE:
			return read_cache_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_FLUSH_WALLET_STORAGE:
			return flush_wallet_storage((Session_data *)sess_ctx, param_types, params);

		case CMD_UPDATE_WALLET_VERSION:
			return update_wallet_version((Session_data *)sess_ctx, param_types, params);

		case CMD_WRITE_CURRENT_WALLET:
			return write_current_wallet_record((Session_data *)sess_ctx, param_types, params);

		case CMD_READ_WALLET_RECORD:
			return read_wallet_record((Session_data *)sess_ctx, param_types, params);

		case CMD_GET_NUM_ADDRESSES:
			return get_number_addresses((Session_data *)sess_ctx, param_types, params);

		case CMD_CHANGE_ENCRYPTION_KEY:
			return change_encryption_key((Session_data *)sess_ctx, param_types, params);

		case CMD_UNINIT_WALLET:
			return uninit_wallet((Session_data *)sess_ctx, param_types, params);

		case CMD_INIT_WALLET:
			return init_wallet((Session_data *)sess_ctx, param_types, params);

		case CMD_GENERATE_RANDOM:
			return generate_random_bytes((Session_data *)sess_ctx, param_types, params);

		case CMD_SET_HMAC_SHA512_KEY:
			return set_hmac_sha512_key((Session_data *)sess_ctx, param_types, params);

		case CMD_SET_HMAC_SHA256_KEY:
			return set_hmac_sha256_key((Session_data *)sess_ctx, param_types, params);

		case CMD_RIPEMD_160:
			return ripemd_160((Session_data *)sess_ctx, param_types, params);

		case CMD_HMAC_SHA512:
			return hmac_sha512((Session_data *)sess_ctx, param_types, params);

		case CMD_HMAC_SHA256:
			return hmac_sha256((Session_data *)sess_ctx, param_types, params);

		case CMD_GENERATE_PASSWORD_BASED_KEY:
			return pbkdf2((Session_data *)sess_ctx, param_types, params);

		case CMD_DERIVE_AND_SET_ENCRYPTION_KEY:
			return derive_and_set_encryption_key((Session_data *)sess_ctx, param_types, params);

		case CMD_SHA256_INIT:
			return sha256_init((Session_data *)sess_ctx, param_types, params);

		case CMD_SHA256_UPDATE:
			return sha256_update((Session_data *)sess_ctx, param_types, params);

		case CMD_SHA256_FINAL:
			return sha256_final((Session_data *)sess_ctx, param_types, params);

		case CMD_SHA256_FINAL_DOUBLE:
			return sha256_final_double((Session_data *)sess_ctx, param_types, params);

		case CMD_GET_WALLET_INFO:
			return get_wallet_info((Session_data *)sess_ctx, param_types, params);

		case CMD_CHANGE_WALLET_NAME:
			return change_wallet_name((Session_data *)sess_ctx, param_types, params);

		case CMD_NEW_WALLET:
			return new_wallet((Session_data *)sess_ctx, param_types, params);

		case CMD_GET_SEED:
			return get_seed((Session_data *)sess_ctx, param_types, params);

		case CMD_GET_ADDRESS_AND_PUB_KEY:
			return get_address_and_public_key((Session_data *)sess_ctx, param_types, params);

		case CMD_SET_TO_G_TEST:
			return set_to_g_test((Session_data *)sess_ctx, param_types, params);

		case CMD_GET_MASTER_PUB_KEY:
			return get_master_public_key((Session_data *)sess_ctx, param_types, params);

		case CMD_MAKE_NEW_ADDRESS:
			return make_new_address((Session_data *)sess_ctx, param_types, params);

		case CMD_ECDSA_SIGN:
			return ecdsa_sign((Session_data *)sess_ctx, param_types, params);

		case CMD_ECDSA_SIGN_TEST:
			return ecdsa_sign_test((Session_data *)sess_ctx, param_types, params);

		case CMD_GENERATE_D256:
			return generate_deterministic256((Session_data *)sess_ctx, param_types, params);

		case CMD_GENERATE_D256_TEST:
			return generate_deterministic256_test((Session_data *)sess_ctx, param_types, params);

		case CMD_GENERATE_D_PUB_KEY_TEST:
			return generate_deterministic_public_key_test((Session_data *)sess_ctx, param_types, params);

		case CMD_SET_ENTROPY_POOL:
			return set_entropy_pool((Session_data *)sess_ctx, param_types, params);

        case CMD_GET_ENTROPY_POOL:
            return get_entropy_pool((Session_data *)sess_ctx, param_types, params);

		case CMD_CLEAR_PRT_PUB_CACHE:
			return clear_parent_public_key_cache((Session_data *)sess_ctx, param_types, params);

		case CMD_GET_PRIVATE_KEY_TEST:
			return get_private_key_test((Session_data *)sess_ctx, param_types, params);

		case CMD_AES_XTS:
			return aes_xts((Session_data *)sess_ctx, param_types, params);

		case CMD_POINT_MULTIPLY_TEST:
			return point_multiply_test((Session_data *)sess_ctx, param_types, params);

		case CMD_ECDSA_SERIALISE:
			return ecdsa_serialise((Session_data *)sess_ctx, param_types, params);

		case CMD_TEST_CALL:
			return test_function((Session_data *)sess_ctx, param_types, params);

		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}
