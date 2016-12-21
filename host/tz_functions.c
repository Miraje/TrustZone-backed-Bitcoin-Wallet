/** \file
  *
  * \brief Consists in all the Client Application functions that interact with
  * Trusted Applications.
  *
  * Manages functions related with the initialization and closing of sessions
  * and contexts as well all the other functions that invoke some command upon
  * trusted applications in the secure world.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "endian.h"
#include "extern.h"
#include "hwinterface.h"
#include "prandom.h"
#include "storage_common.h"
#include "test_performance.h"
#include "tz_functions.h"
#include "user_interface.h"
#include "wallet_ta.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <tee_client_api.h>

/* TODO CONFIRM THAT WHEN TESTING IS NOT INCLUDED ALL THE FUNCTIONS ARE NOT COMPILED */

/** Used to contain control information related to the context between the CA
  * and the TEE. */
TEEC_Context context;

/** Used to contain control information related to the session between the CA
  * and the TA */
TEEC_Session session;

/**
  * Convert an byte array with 32 positions to a 32 bit unsigned integer array
  * with 8 position in big-endian format.
  * \param array_src The source byte array.
  * \param array_dest The destine byte array.
  */
void convertFrom8To32BE(uint8_t * array_src, uint32_t * array_dest)
{
    uint8_t i;

    for (i = 0; i < 32; i += 4)
        array_dest[i/4] = (array_src[i] << 24)
                            | (array_src[i+1] << 16)
                            | (array_src[i+2] << 8)
                            | array_src[i+3];
}

/**
  * Write the hash value into a byte array, respecting endianness.
  * \param out The byte array which will receive the hash. This byte array
  *            must have space for at least 32 bytes, even if the hash
  *            function's result is smaller than 256 bits.
  * \param hash The hash.
  * \param do_write_big_endian Whether the hash should be written in a
  *                            big-endian way (useful for computing the first
  *                            hash of a double SHA-256 hash) instead of a
  *                            little-endian way (useful for sending off to a
  *                            signing function).
  * \warning hashFinish() (or the appropriate hash-specific finish function)
  *          must be called before this function.
  */
void writeHashToByteArrayTZ(uint8_t *out, uint32_t * hash, bool do_write_big_endian)
{
    uint8_t i;

    if (do_write_big_endian)
    {
        for (i = 0; i < 8; i++)
            writeU32BigEndian(&(out[i * 4]), hash[i]);
    }
    else
    {
        for (i = 0; i < 8; i++)
            writeU32LittleEndian(&(out[i * 4]), hash[7 - i]);
    }
}

/**
  * Initializes a new TEE context and opens a new session with all trusted
  * applications.
  * \warning This functions only initializes, in the end it is necessary to call
  *          terminateTZ() for a clean exit.
  */
void initialiseTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_UUID uuid = WALLET_TA_UUID;
    uint32_t error_origin;

    /*
     * Initialize a new TEE Context, forming a connection between this Client
     * Application and the TEE.
     */
    result = TEEC_InitializeContext(NULL, &context);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", result);

    /*
     * Open a new session between the Client Application and the Trusted
     * Application (identified by a UUID).
     * Currently the only connectionMethod supported is TEEC_LOGIN_PUBLIC.
     */
    result = TEEC_OpenSession(
                    &context,
                    &session,
                    &uuid,
                    TEEC_LOGIN_PUBLIC,
                    NULL,
                    NULL,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        /*
         * The context should be finalized when the connection with the TEE is
         * no longer required, allowing resources to be released. This function
         * must only be called when all session inside this TEE context have
         * been closed and all shared memory blocks have been released.
         */
        TEEC_FinalizeContext(&context);

        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", result, error_origin);
    }

    /* Initialize the operation handles in the Trusted Application */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_INITIALIZE_HANDLERS,
                    NULL,
                    &error_origin);

    if(result != TEEC_SUCCESS)
    {
        /*
         * The context should be finalized when the connection with the TEE is
         * no longer required, allowing resources to be released. This function
         * must only be called when all session inside this TEE context have
         * been closed and all shared memory blocks have been released.
         */
        TEEC_FinalizeContext(&context);

        errx(1, "TEEC_InvokeCommand for CMD_INITIALIZE_HANDLERS failed with code 0x%x origin 0x%x", result, error_origin);
    }
}

/**
  * Finalizes the TEE context and closes all sessions opened with all the
  * trusted applications.
  * \return TEEC_SUCCESS in case of success otherwise returns the result
  *         received from the failed operation. The information about all
  *         possible returns is present in TEE Client API Specification - 4.4.2.
  * \warning Should only be called if initialiseTZ() was called first,
  */
void terminateTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    uint32_t error_origin;

    result = TEEC_InvokeCommand(
                    &session,
                    CMD_FINALIZE_HANDLERS,
                    NULL,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        fprintf(stderr, "TEEC_InvokeCommand for CMD_FINALIZE_HANDLERS failed with code 0x%x origin 0x%x\n", result, error_origin);

    /*
     * Closes the session opened with the Trusted Application. All the commands
     * within the session must have completed before calling this function
     */
    TEEC_CloseSession(&session);

    /*
     * The context should be finalized when the connection with the TEE is
     * no longer required, allowing resources to be released. This function
     * must only be called when all session inside this TEE context have
     * been closed and all shared memory blocks have been released.
     */
    TEEC_FinalizeContext(&context);
}

/**
  * Encrypt an source using AES in XTS mode. This uses the encryption
  * key set by deriveAndSetEncryptionKeyTZ().
  * \param mode The mode of operation: 0 for encryption, 1 for decryption.
  * \param source The source buffer. For encryption mode it should be the
  *               plaintext and for decryption mode it should be ciphertext.
  * \param source_len Size of the source buffer (in bytes).
  * \param dest The destination buffer. For encryption mode it should be the
  *               ciphertext and for decryption mode it should be plaintext.
  * \param dest_len Size of the source buffer (in bytes).
  */
void aesXTS(int mode, uint8_t * source, uint32_t source_len, uint8_t * dest, uint32_t dest_len)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IO]  params[0].memref.buffer -> Source data to encrypt or decrypt.
     * [IO]  params[0].memref.size   -> Size of the source data.
     * [IO]  params[1].memref.buffer -> Destination data of the encryption or
     *                                  decryption.
     * [IO]  params[1].memref.size   -> Size of destination data.
     * [IN]  params[2].value.a       -> Mode of operation (encryption -0 or
     *                                  decryption -1).
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INOUT,
                                TEEC_MEMREF_TEMP_INOUT,
                                TEEC_VALUE_INPUT,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)source;
    operation.params[0].tmpref.size = (size_t)source_len;
    operation.params[1].tmpref.buffer = (uint8_t*)dest;
    operation.params[1].tmpref.size = (size_t)dest_len;
    operation.params[2].value.a = (uint32_t)mode;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_AES_XTS,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_GET_PRIVATE_KEY_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);
}

/**
  * Encrypt an source using AES in XTS mode. This uses the encryption
  * key set by deriveAndSetEncryptionKeyTZ().
  * \param mode The mode of operation: 0 for encryption, 1 for decryption.
  * \param source The source buffer. For encryption mode it should be the
  *               plaintext and for decryption mode it should be ciphertext.
  * \param source_len Size of the source buffer (in bytes).
  * \param dest The destination buffer. For encryption mode it should be the
  *               ciphertext and for decryption mode it should be plaintext.
  * \param dest_len Size of the source buffer (in bytes).
  */
void ripemd160TZ(uint8_t *message, uint32_t length, uint32_t *h)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].memref.buffer -> Source data to hash.
     * [IN]  params[0].memref.size   -> Size of the source data.
     * [OUT] params[1].memref.buffer -> Destination data of the hash.
     * [OUT]  params[1].memref.size   -> Size of destination data.
     */
	operation.paramTypes = TEEC_PARAM_TYPES(
							TEEC_MEMREF_TEMP_INPUT,
							TEEC_MEMREF_TEMP_OUTPUT,
							TEEC_NONE,
							TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)message;
    operation.params[0].tmpref.size = (size_t)length;
    operation.params[1].tmpref.buffer = (uint32_t*)h;
    operation.params[1].tmpref.size = (size_t)20;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_RIPEMD_160,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_RIPEMD_160 failed with code 0x%x origin 0x%x\n", result, error_origin);
}

/**
  * Begin calculating hash for new message. Invokes the command in the Trusted
  * Application.
  * \param sha_256_op_handler The SHA-256 operation handler number. There are 4
  *                           different handlers available (from 1 to 4) this
  *                           means that it could be (only) 4 different SHA-256
  *                           operations running simultaneously.
  */
void sha256BeginTZ(int sha_256_op_handler)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].value.a -> SHA operation handler number.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].value.a = (uint32_t)sha_256_op_handler;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SHA256_INIT,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SHA256_INIT failed with code 0x%x origin 0x%x", result, error_origin);
}

/**
  * Add #text_size bytes to the message hashed. Invokes the command in the
  * Trusted Application.
  * \param text The bytes to add.
  * \param text_size The number of bytes to add.
  * \param sha_256_op_handler The SHA-256 operation handle to act on. It must be
  *                           one that has been initialized using
  *                           sha256BeginTZ() at some time in the past.
  */
void sha256WriteTZ(uint8_t * text, uint32_t text_size, int sha_256_op_handler)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].memref.buffer -> Text.
     * [IN]  params[0].memref.size   -> Length of the text.
     * [IN]  params[1].value.a -> SHA operation handler number.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)text;
    operation.params[0].tmpref.size = (size_t)text_size;
    operation.params[1].value.a = (uint32_t)sha_256_op_handler;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SHA256_UPDATE,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SHA256_UPDATE failed with code 0x%x origin 0x%x", result, error_origin);
}

/**
  * Finalize the hashing of a message. Invokes the command in the Trusted
  * Application.
  * \param hash The buffer that will contain the hashed message.
  * \param hash_len Size of the #hash buffer. It must be 32 bytes.
  * \param sha_256_op_handler The SHA-256 operation handler to act on. It must
  *                           be one that has been initialized using
  *                           sha256BeginTZ() at some time in the past.
  */
void sha256FinishTZ(uint32_t * hash, uint32_t hash_len, int sha_256_op_handler)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;
    uint8_t h[32];

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Buffer where the hashed message will be
     *                                  written.
     * [OUT] params[0].memref.size   -> Length of the buffer.
     * [IN]  params[1].value.a       -> SHA operation handler number.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)h;
    operation.params[0].tmpref.size = (size_t)hash_len;
    operation.params[1].value.a = (uint32_t)sha_256_op_handler;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SHA256_FINAL,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SHA256_FINAL failed with code 0x%x origin 0x%x", result, error_origin);

    /*
     * As the hashed message is in array of 8 bits unsigned integers it is
     * needed to convert the array into a array of 32 bits unsigned integers for
     * the requested output
     */
    convertFrom8To32BE(h, hash);
}

/**
  * Finalize the hashing of a message just like sha256FinishTZ(), except this
  * does a double SHA-256 hash. A double SHA-256 hash is sometimes used in the
  * Bitcoin protocol. Invokes the command in the Trusted Application.
  * \param hash The buffer that will contain the hashed message.
  * \param hash_len Size of the #hash buffer. It must be 32 bytes.
  * \param sha_256_op_handler The SHA-256 operation handler to act on. It must
  *                           be one that has been initialized using
  *                           sha256BeginTZ() at some time in the past.
  */
void sha256FinishDoubleTZ(uint32_t * hash, uint32_t hash_len, int sha_256_op_handler)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;
    uint8_t h[32];

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Buffer where the hashed message will be
     *                                  written.
     * [OUT] params[0].memref.size   -> Length of the buffer.
     * [IN]  params[1].value.a       -> SHA operation handler number.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)h;
    operation.params[0].tmpref.size = (size_t)hash_len;
    operation.params[1].value.a = (uint32_t)sha_256_op_handler;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SHA256_FINAL_DOUBLE,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SHA256_FINAL failed with code 0x%x origin 0x%x", result, error_origin);

    /*
     * As the hashed message is in array of 8 bits unsigned integers it is
     * needed to convert the array into a array of 32 bits unsigned integers for
     * the requested output
     */
    convertFrom8To32BE(h, hash);
}

/**
  * Invokes a command in the Trusted Application to set the hmac-sha-512 key.
  * \param key A byte array containing the key to use in the HMAC-SHA512
  *            calculation. The key can be of any length.
  * \param key_length The length, in bytes, of the key.
  */
void setHmacSha512KeyTZ(const uint8_t *key, const unsigned int key_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    memset(&operation, 0, sizeof(operation));

    /*
     * Set the operation parameter types. params[0] will contain the key and as
     * such it is defined as input
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    /* Set the parameters */
    operation.params[0].tmpref.buffer = (uint8_t*)key;
    operation.params[0].tmpref.size = (size_t)key_length;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SET_HMAC_SHA512_KEY,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SET_HMAC_SHA512_KEY failed with code 0x%x origin 0x%x", result, error_origin);
}

/**
  * Invokes a command in the Trusted Application to calculate a 64 byte HMAC of
  * an arbitrary message and key using SHA-512 as the hash function.
  * \param out A byte array where the HMAC-SHA512 hash value will be written.
  * \param text A byte array containing the message to use in the HMAC-SHA512
  *             calculation. The message can be of any length.
  * \param text_length The length, in bytes, of the message.
  */
void hmacSha512TZ(uint8_t *out, const uint8_t *text, const unsigned int text_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Clear the content of the output buffer */
    memset(out, 0, SHA512_HASH_LENGTH);

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Defining the parameters type. params[0] will have the output and
     * params[1] will have the input text
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    /* Setting the operation parameters */
    operation.params[0].tmpref.buffer = (uint8_t*)out;
    operation.params[0].tmpref.size = (size_t)SHA512_HASH_LENGTH;
    operation.params[1].tmpref.buffer = (uint8_t*)text;
    operation.params[1].tmpref.size = (size_t)text_length;

    /* Invoking the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_HMAC_SHA512,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_HMAC_SHA512 failed with code 0x%x origin 0x%x", result, error_origin);
}

/**
  * Invokes a command in the Trusted Application to set the hmac-sha-256 key.
  * \param key A byte array containing the key to use in the HMAC-SHA256
  *            calculation. The key can be of any length.
  * \param key_length The length, in bytes, of the key.
  */
void setHmacSha256KeyTZ(const uint8_t *key, const unsigned int key_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup the operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Set the operation parameter types. params[0] will contain the key and as
     * such it is defined as input
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    /* Set the parameters */
    operation.params[0].tmpref.buffer = (uint8_t*)key;
    operation.params[0].tmpref.size = (size_t)key_length;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SET_HMAC_SHA256_KEY,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SET_HMAC_SHA256_KEY failed with code 0x%x origin 0x%x", result, error_origin);
}

/**
  * Invokes a command in the Trusted Application to calculate a 32 byte HMAC of
  * an arbitrary message and key using SHA-256 as the hash function.
  * \param out A byte array where the HMAC-SHA256 hash value will be written.
  * \param text A byte array containing the message to use in the HMAC-SHA256
  *             calculation. The message can be of any length.
  * \param text_length The length, in bytes, of the message.
  */
void hmacSha256TZ(uint8_t *out, const uint8_t *text1, const unsigned int text_length1, const uint8_t *text2, const unsigned int text_length2)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Clear the output buffer */
    memset(out, 0, SHA256_HASH_LENGTH);

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Defining the parameters type. params[0] will have the output and
     * params[1] will have the input text
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE);

    /* Setting the operation parameters */
    operation.params[0].tmpref.buffer = (uint8_t*)out;
    operation.params[0].tmpref.size = (size_t)SHA256_HASH_LENGTH;
    operation.params[1].tmpref.buffer = (uint8_t*)text1;
    operation.params[1].tmpref.size = (size_t)text_length1;
    operation.params[2].tmpref.buffer = (uint8_t*)text2;
    operation.params[2].tmpref.size = (size_t)text_length2;

    /* Invoking the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_HMAC_SHA256,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_HMAC_SHA256 failed with code 0x%x origin 0x%x", result, error_origin);
}

/**
  * Invokes a command in the Trusted Application for the creation of the wallet
  * secure storage.
  * \warning This function only created the storage does not open it (for that
  *          see #openWalletStorageTZ()).
  */
void createWalletStorageTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Wallet storage id (name) */
    char wallet_storage_id[] = "wallet_storage";

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a temporary input buffer for sending the name of the wallet storage
     * to the Trusted Application
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = wallet_storage_id;
    operation.params[0].tmpref.size = sizeof(wallet_storage_id);

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_CREATE_WALLET_STORAGE,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_CREATE_WALLET_STORAGE failed with code 0x%x origin 0x%x", result, error_origin);
}

/**
  * Invokes a command in the Trusted Application to open the wallet secure
  * storage for writing and reading.
  * \warning If the storage is not yet created or is already open it will return
  *          an error.
  */
void openWalletStorageTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    uint32_t error_origin;

    result = TEEC_InvokeCommand(
                    &session,
                    CMD_OPEN_WALLET_STORAGE,
                    NULL,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_OPEN_WALLET_STORAGE failed with code 0x%x origin 0x%x", result, error_origin);
}

/** Invokes a command in the Trusted Application to close the wallet storage.
  * \warning If this function is called before the storage is opened it will
  *          return an error.
  */
void closeWalletStorageTZ(void)
{
    TEEC_Result result;
    uint32_t error_origin;

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_CLOSE_WALLET_STORAGE,
                    NULL,
                    &error_origin);

    /*
     * This should never happen as the command always return TEEC_SUCCESS. But
     * for just to cover possible changes it is safer to assume that it in
     * future it could be possible to receive other returns.
     */
    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_CLOSE_WALLET_STORAGE failed with code 0x%x origin 0x%x", result, error_origin);
}

/** Invokes a command in the Trusted Application to delete the wallet secure
  * storage. The storage do not need to be closed to be deleted.
  * \warning If this function is called before a storage is created it will
  *          return an error.
  */
void deleteWalletStorageTZ(void)
{
    TEEC_Result result;
    uint32_t error_origin;

    result = TEEC_InvokeCommand(
                    &session,
                    CMD_DELETE_WALLET_STORAGE,
                    NULL,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_DELETE_WALLET_STORAGE failed with code 0x%x origin 0x%x", result, error_origin);
}

/** Invokes a command in the Trusted Application to set the position of the data
  * stream on the wallet secure storage to the one indicated in the argument.
  * \param address The position to set the data stream in wallet storage.
  * \warning If this function is called before a storage is created or opened
  *          it will return an error.
  */
void seekWalletStorageTZ(int32_t address)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a 32 bit integer to send the address.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].value.a = (uint32_t)address;

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SEEK_WALLET_STORAGE,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SEEK_WALLET_STORAGE failed with code 0x%x origin 0x%x", result, error_origin);
}

/** Invokes a command in the Trusted Application to write one byte in the wallet
  * storage.
  * \param inputBuffer A pointer to the buffer that contains the data to be
  *                    written.
  */
void write1ByteWalletStorageTZ(uint8_t * inputBuffer)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a temporary input buffer for sending the data to be written.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)inputBuffer;
    operation.params[0].tmpref.size = (size_t)1;

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_WRITE1_WALLET_STORAGE,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_WRITE1_WALLET_STORAGE failed with code 0x%x origin 0x%x", result, error_origin);
}

/** Invokes a command in the Trusted Application to read one byte from the
  * wallet storage.
  * \param outputBuffer A pointer to the buffer were the read data will be
  *                    written to.
  */
void read1ByteWalletStorageTZ(uint8_t * outputBuffer)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /*
     * It is necessary to fill the outputBuffer with zeros because if the address
     * indicates a position at, or past, the end of the data when reading then
     * no bytes are copied and as such at least there is the guarantee that it
     * is not random data that stays in the outputBuffer. It is not a great
     * solution but for debug purposes it can help a lot.
     */
    memset(outputBuffer, 0, 1);

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a temporary output buffer for receiving the data read.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)outputBuffer;
    operation.params[0].tmpref.size = (size_t)1;

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_READ1_WALLET_STORAGE,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_READ1_WALLET_STORAGE failed with code 0x%x origin 0x%x", result, error_origin);
}

/** Invokes a command in the Trusted Application to write in the wallet storage.
  * \param inputBuffer A pointer to the buffer that contains the data to be
  *                    written.
  * \param length The amount of bytes to write in the wallet storage.
  * \param address Byte offset specifying where in the partition to
  *                start writing to.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn writeWalletStorageTZ(uint8_t * inputBuffer, uint32_t length, int32_t address)
{
    NonVolatileReturn nv_error;
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a temporary input buffer for sending the data to be written.
     * Use a 32 bit integer to send the address.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)inputBuffer;
    operation.params[0].tmpref.size = (size_t)length;
    operation.params[1].value.a = (uint32_t)address;

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_WRITE_WALLET_STORAGE,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_WRITE_WALLET_STORAGE failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "NonVolatileReturn: %d\n", operation.params[1].value.b);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_WRITE_WALLET_STORAGE failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    nv_error = (NonVolatileReturn)(operation.params[1].value.b);

    return nv_error;
}

/** Invokes a command in the Trusted Application to read from the wallet storage.
  * \param outputBuffer A pointer to the buffer were the read data will be
  *                    written to.
  * \param length The amount of bytes to read from the wallet storage.
  * \param address Byte offset specifying where in the partition to
  *                start reading from.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn readWalletStorageTZ(uint8_t * outputBuffer, uint32_t length, int32_t address)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /*
     * It is necessary to fill the outputBuffer with zeros because if the address
     * indicates a position at, or past, the end of the data when reading then
     * no bytes are copied and as such at least there is the guarantee that it
     * is not random data that stays in the outputBuffer. It is not a great
     * solution but for debug purposes it can help a lot.
     */
    memset(outputBuffer, 0, length);

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a temporary output buffer for receiving the data read.
     * Use a 32 bit integer to send the address.
     * Use a 32 bit integer to receive the number of bytes read.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)outputBuffer;
    operation.params[0].tmpref.size = (size_t)length;
    operation.params[1].value.a = (uint32_t)address;

    /*
     * The amount of bytes actually read is located at
     * operation.params[1].value.b but this cannot be compared with 'length'
     * because some times (like in the initialization wallet operation) there is
     * not anything to be read and as such the size read would be 0 different
     * from length. This situation is not an error and as such that parameter
     * can not be used to check if the read was successful.
     */

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_READ_WALLET_STORAGE,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_READ_WALLET_STORAGE failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "NonVolatileReturn: %d\n", (uint32_t)NV_IO_ERROR);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_READ_WALLET_STORAGE failed with code 0x%x origin 0x%x\n", result, error_origin);
        }

        return NV_IO_ERROR;
    }

    return NV_NO_ERROR;
}

/** Invokes a command in the Trusted Application to flush all buffered write
  * into the wallet secure storage.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning If this function is called before a storage is created or opened
  *          it will return an error.
  */
NonVolatileReturn flushWalletStorageTZ(void)
{
    NonVolatileReturn nv_error = NV_IO_ERROR;
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a temporary output buffer for receiving the data read.
     * Use a 32 bit integer to send the address.
     * Use a 32 bit integer to receive the number of bytes read.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    result = TEEC_InvokeCommand(
                    &session,
                    CMD_FLUSH_WALLET_STORAGE,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_FLUSH_WALLET_STORAGE failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "NonVolatileReturn: %d\n", operation.params[0].value.a);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_FLUSH_WALLET_STORAGE failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    nv_error = (NonVolatileReturn)(operation.params[0].value.a);

    return nv_error;
}

/* TODO REMOVE THIS FUNCTION */

/** Invokes a command in the Trusted Application to Derive a key using the
  * specified password and salt using HMAC-SHA512 as the underlying
  * pseudo-random function.
  * \param out A byte array where the resulting derived key will be written.
  *            This must have space for #SHA512_HASH_LENGTH bytes.
  * \param password Byte array specifying the password to use in PBKDF2.
  * \param password_length The length (in bytes) of the password.
  * \param salt Byte array specifying the salt to use in PBKDF2.
  * \param salt_length The length (in bytes) of the salt.
  * \warning salt cannot be too long; salt_length must be less than or equal
  *          to #SHA512_HASH_LENGTH - 4.
  */
void pbkdf2TZ(uint8_t *out, const uint8_t *password, const unsigned int password_length, const uint8_t *salt, const unsigned int salt_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Clear the output buffer */
    memset(out, 0, SHA512_HASH_LENGTH);

    /* Setup the operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The derived key.
     * [OUT] params[0].memref.size   -> Size of the derived key.
     * [IN]  params[1].memref.buffer -> Password.
     * [IN]  params[1].memref.size   -> Size of password.
     * [IN]  params[2].memref.buffer -> Salt.
     * [IN]  params[2].memref.size   -> Size of salt.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)out;
    operation.params[0].tmpref.size = (size_t)SHA512_HASH_LENGTH;
    operation.params[1].tmpref.buffer = (uint8_t*)password;
    operation.params[1].tmpref.size = (size_t)password_length;
    operation.params[2].tmpref.buffer = (uint8_t*)salt;
    operation.params[2].tmpref.size = (size_t)salt_length;

    /* Invoking the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GENERATE_PASSWORD_BASED_KEY,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_GENERATE_PASSWORD_BASED_KEY failed with code 0x%x origin 0x%x", result, error_origin);
}

#ifdef TESTING

/**
  * Invokes a command in the Trusted Application to preform the scalar
  * multiplication. This function is not needed for the correct functioning of
  * the wallet it is only used for testing purposes.
  * \param p The point (in affine coordinates) to multiply.
  * \param k The 32 byte multi-precision scalar to multiply p by.
  */
void pointMultiplyTestTZ(PointAffine *p, BigNum256 k)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IO]  params[0].memref.buffer -> The point (in affine coordinates) to multiply.
     * [IO]  params[0].memref.size   -> Size of the point.
     * [IN]  params[1].memref.buffer -> The 32 byte multi-precision scalar to multiply p by.
     * [IN]  params[1].memref.size   -> Size of the scalar point.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INOUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (PointAffine*)p;
    operation.params[0].tmpref.size = (size_t)sizeof(PointAffine);
    operation.params[1].tmpref.buffer = (BigNum256)k;
    operation.params[1].tmpref.size = (size_t)32;

    /* Invoke the command. */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_POINT_MULTIPLY_TEST,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_POINT_MULTIPLY_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);
}

/**
  * Invokes a command in the Trusted Application to set a point to the base
  * point of secp256k1. This function is not really needed for the correct
  * functioning of the wallet it is only used for testing purposes.
  * \param p The point to set.
  */
void setToGTestTZ(PointAffine *p)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The point to set..
     * [OUT] params[0].memref.size   -> Size of the point to set.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (PointAffine*)p;
    operation.params[0].tmpref.size = (size_t)sizeof(PointAffine);

    /* Invoke command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SET_TO_G_TEST,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_SET_TO_G_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);
}

#endif

/** Invokes a command in the Trusted Application to serialise an elliptic curve
  * point in a manner which is Bitcoin-compatible.
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
uint8_t ecdsaSerialiseTZ(uint8_t *out, const PointAffine *point, const bool do_compress)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The point to set..
     * [OUT] params[0].memref.size   -> Size of the point to set.
     * [IN]  params[1].memref.buffer -> The point to set..
     * [IN]  params[1].memref.size   -> Size of the point to set.
     * [IN]  params[2].value.a       -> Boolean with info about compression.
     * [OUT] params[2].value.b       -> The number of bytes written to out.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)out;
    operation.params[0].tmpref.size = (size_t)ECDSA_MAX_SERIALISE_SIZE;
    operation.params[1].tmpref.buffer = (PointAffine*)point;
    operation.params[1].tmpref.size = (size_t)sizeof(PointAffine);
    operation.params[2].value.a = (uint32_t)do_compress;

    /* Invoke command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_ECDSA_SERIALISE,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_ECDSA_SERIALISE failed with code 0x%x origin 0x%x\n", result, error_origin);

    return (uint8_t)(operation.params[2].value.b);
}

/** Invokes a command in the Trusted Application to sign a transaction.
  * \param r The "r" component of the signature will be written to here as
  *          a 32 byte multi-precision number.
  * \param s The "s" component of the signature will be written to here, as
  *          a 32 byte multi-precision number.
  * \param hash The message digest of the message to sign, represented as a
  *             32 byte multi-precision number.
  * \param ah The address handle to obtain the key of.
  */
WalletErrors ecdsaSignTZ(BigNum256 r, BigNum256 s, const BigNum256 hash, AddressHandle ah)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The "r" component of the signature.
     * [OUT] params[0].memref.size   -> Size of "r".
     * [OUT] params[1].memref.buffer -> The "s" component of the signature.
     * [OUT] params[1].memref.size   -> Size of "s".
     * [IN]  params[2].memref.buffer -> The message digest of the message to sign.
     * [IN]  params[2].memref.size   -> Size of message.
     * [IN]  params[3].value.a       -> AddressHandle of the private key.
     * [OUT] params[3].value.b       -> WalletErrors return of get private key.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INOUT);

    operation.params[0].tmpref.buffer = (BigNum256)r;
    operation.params[0].tmpref.size = (size_t)32;
    operation.params[1].tmpref.buffer = (BigNum256)s;
    operation.params[1].tmpref.size = (size_t)32;
    operation.params[2].tmpref.buffer = (BigNum256)hash;
    operation.params[2].tmpref.size = (size_t)32;
    operation.params[3].value.a = (uint32_t)ah;

    /* Invoke command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_ECDSA_SIGN,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_ECDSA_SIGN failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[3].value.b);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_ECDSA_SIGN failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    /* Set the wallet last error */
    last_error = (WalletErrors)(operation.params[3].value.b);

    return last_error;
}

#ifdef TESTING

/** Invokes a command in the Trusted Application to sign a transaction.
  * This function is not really needed for the correct
  * functioning of the wallet it is only used for testing purposes.
  * \param r The "r" component of the signature will be written to here as
  *          a 32 byte multi-precision number.
  * \param s The "s" component of the signature will be written to here, as
  *          a 32 byte multi-precision number.
  * \param hash The message digest of the message to sign, represented as a
  *             32 byte multi-precision number.
  * \param private_key The private key to use in the signing operation,
  *                    represented as a 32 byte multi-precision number.
  */
void ecdsaSignTestTZ(BigNum256 r, BigNum256 s, const BigNum256 hash, const BigNum256 private_key)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The "r" component of the signature.
     * [OUT] params[0].memref.size   -> Size of "r".
     * [OUT] params[1].memref.buffer -> The "s" component of the signature.
     * [OUT] params[1].memref.size   -> Size of "s".
     * [IN]  params[2].memref.buffer -> The message digest of the message to sign.
     * [IN]  params[2].memref.size   -> Size of message.
     * [IN]  params[2].memref.buffer -> Private key.
     * [IN]  params[2].memref.size   -> Size of the private key.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INPUT);

    operation.params[0].tmpref.buffer = (BigNum256)r;
    operation.params[0].tmpref.size = (size_t)32;
    operation.params[1].tmpref.buffer = (BigNum256)s;
    operation.params[1].tmpref.size = (size_t)32;
    operation.params[2].tmpref.buffer = (BigNum256)hash;
    operation.params[2].tmpref.size = (size_t)32;
    operation.params[3].tmpref.buffer = (BigNum256)private_key;
    operation.params[3].tmpref.size = (size_t)32;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_ECDSA_SIGN_TEST,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_ECDSA_SIGN_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);
}

/** Invokes a command in the Trusted Application to deterministically
  * generate a new public key. This function is not really needed for the
  * correct functioning of the wallet it is only used for testing purposes.
  * \param out_public_key The generated public key will be written here.
  * \param in_parent_public_key The parent public key, referred to as K_par in
  *                             the article above.
  * \param chain_code Should point to a byte array of length 32 containing
  *                   the BIP 0032 chain code.
  * \param num A counter which determines which number the pseudo-random
  *            number generator will output.
  */
void generateDeterministicPublicKeyTestTZ(PointAffine *out_public_key, PointAffine *in_parent_public_key, const uint8_t *chain_code, const uint32_t num)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The generated public key.
     * [OUT] params[0].memref.size   -> Size of the generated public key.
     * [IN]  params[1].memref.buffer -> The parent public key.
     * [IN]  params[1].memref.size   -> Length of the parent public key.
     * [IN]  params[2].memref.buffer -> Byte array of length 32 containing the
     *                                  BIP 0032 chain code.
     * [IN]  params[2].memref.size   -> Length of the the array.
     * [IN]  params[3].value.a       -> The counter.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INPUT);

    operation.params[0].tmpref.buffer = (PointAffine*) out_public_key;
    operation.params[0].tmpref.size = (size_t)sizeof(PointAffine);
    operation.params[1].tmpref.buffer = (PointAffine*) in_parent_public_key;
    operation.params[1].tmpref.size = (size_t)sizeof(PointAffine);
    operation.params[2].tmpref.buffer = (uint8_t*)chain_code;
    operation.params[2].tmpref.size = (size_t)32;
    operation.params[3].value.a = (uint32_t)num;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GENERATE_D_PUB_KEY_TEST,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_GENERATE_D_PUB_KEY_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);
}

#endif

/** Clear the parent public key cache. This should be called whenever a wallet
  * is unloaded, so that subsequent calls to generateDeterministic256TZ() don't
  * result in addresses from the old wallet.
  */
void clearParentPublicKeyCacheTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    uint32_t error_origin;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_CLEAR_PRT_PUB_CACHE,
                    NULL,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_CLEAR_PRT_PUB_CACHE failed with code 0x%x origin 0x%x\n", result, error_origin);
}

/** Invokes a command in the Trusted Application to get random bytes.
  * \param randomBuffer A pointer to the buffer were the random data will be
  *                     written to.
  * \param numRandomBytes The amount of random bytes needed.
  * \warning The randomBuffer should have enough space for numRandomBytes.
  */
void generateRandomBytesTZ(uint8_t * randomBuffer, uint32_t numRandomBytes)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Erase the content of the random buffer */
    memset(randomBuffer, 0, numRandomBytes);

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Use a temporary output buffer for receiving the random data.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)randomBuffer;

    /*
     * This is not necessarily the size of the randomBuffer. We will be using
     * as the number of random bytes we want.
     */
    operation.params[0].tmpref.size = (size_t)numRandomBytes;

    /*
     * The command invocation blocks the Client Application thread, waiting for
     * an answer from the Trusted Application.
     */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GENERATE_RANDOM,
                    &operation,
                    &error_origin);

    /*
     * This will probably only happen if the TEE panics because otherwise the
     * return is always TEE_SUCCESS
     */
    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_GENERATE_RANDOM failed with code 0x%x origin 0x%x", result, error_origin);
}

bool setEntropyPoolTZ(uint8_t *in_pool_state)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].memref.buffer -> Input pool state;
     * [IN]  params[0].memref.size   -> Size of the input pool state;
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)in_pool_state;
    operation.params[0].tmpref.size = (size_t)ENTROPY_POOL_LENGTH;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_SET_ENTROPY_POOL,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        #ifdef DEBUG
        fprintf(stderr, "TEEC_InvokeCommand for CMD_SET_ENTROPY_POOL failed with code 0x%x origin 0x%x\n", result, error_origin);
        #endif
        return true;
    }

    return false;
}

bool getEntropyPoolTZ(uint8_t * out_pool_state)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

   /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Entropy pool read.
     * [OUT] params[0].memref.size   -> Size of the entropy pool.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)out_pool_state;
    operation.params[0].tmpref.size = (size_t)ENTROPY_POOL_LENGTH;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GET_ENTROPY_POOL,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        #ifdef DEBUG
        fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_ENTROPY_POOL failed with code 0x%x origin 0x%x\n", result, error_origin);
        #endif
        return true;
    }

    return false;
}


/** Invokes a command in the Trusted Application to deterministically
  * generate a new 256 bit number.
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
  * \return false upon success, true if the specified seed is not valid (will
  *         produce degenerate private keys).
  */
bool generateDeterministic256TZ(BigNum256 out, const uint8_t *seed, const uint32_t num)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;
    bool gd256_result;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The generated 256 bit number.
     * [OUT] params[0].memref.size   -> Size of the generated number.
     * [IN]  params[1].memref.buffer -> The seed for the pseudo-random number generator
     * [IN]  params[1].memref.size   -> Length of the seed.
     * [IN]  params[2].value.a       -> The counter.
     * [OUT] params[2].value.b       -> Result.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (BigNum256)out;
    operation.params[0].tmpref.size = (size_t)32;
    operation.params[1].tmpref.buffer = (uint8_t*)seed;
    operation.params[1].tmpref.size = (size_t)SEED_LENGTH;
    operation.params[2].value.a = (uint32_t)num;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GENERATE_D256,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_GENERATE_D256 failed with code 0x%x origin 0x%x\n", result, error_origin);

    /* Get the result obtained from the TA */
    gd256_result = (bool)(operation.params[2].value.b);

    return gd256_result;
}

#ifdef TESTING

/** Invokes a command in the Trusted Application to deterministically
  * generate a new 256 bit number. This function differs from
  * generateDeterministic256TZ() in output parameters of the TA function called.
  * Here it is set the variable #test_chain_code. This function is not really
  * needed for the correct functioning of the wallet it is and should only be
  * used for testing purposes.
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
  * \return false upon success, true if the specified seed is not valid (will
  *         produce degenerate private keys).
  */
bool generateDeterministic256TestTZ(BigNum256 out, const uint8_t *seed, const uint32_t num)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;
    bool gd256_result;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The generated 256 bit number.
     * [OUT] params[0].memref.size   -> Size of the generated number.
     * [IN]  params[1].memref.buffer -> The seed for the pseudo-random number generator
     * [IN]  params[1].memref.size   -> Length of the seed.
     * [IN]  params[2].value.a       -> The counter.
     * [OUT] params[2].value.b       -> Result.
     * [OUT] params[3].memref.buffer -> Derived chain code.
     * [OUT] params[3].memref.size   -> Size of the derived chain code.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_MEMREF_TEMP_OUTPUT);

    operation.params[0].tmpref.buffer = (BigNum256)out;
    operation.params[0].tmpref.size = (size_t)32;
    operation.params[1].tmpref.buffer = (uint8_t*)seed;
    operation.params[1].tmpref.size = (size_t)SEED_LENGTH;
    operation.params[2].value.a = (uint32_t)num;
    operation.params[3].tmpref.buffer = (BigNum256)test_chain_code;
    operation.params[3].tmpref.size = (size_t)32;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GENERATE_D256_TEST,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_GENERATE_D256_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);

    /* Get the result obtained from the TA */
    gd256_result = (bool)(operation.params[2].value.b);

    return gd256_result;
}

#endif

/** Invokes a command in the Trusted Application to update the wallet version.
  * \return See #WalletErrors.
  */
WalletErrors updateWalletVersionTZ(void)
{
    TEEC_Result result;
    uint32_t error_origin;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_UPDATE_WALLET_VERSION,
                    NULL,
                    &error_origin);

    if(result != TEEC_SUCCESS)
    {
        /*
         * If the result is TEEC_ERROR_BAD_STATE that means that the operation
         * wasn't successful but the error was defined as one of the possible
         * returns
         */
        if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_UPDATE_WALLET_VERSION failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)WALLET_INVALID_OPERATION);
            #endif

            return WALLET_INVALID_OPERATION;
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_UPDATE_WALLET_VERSION failed with code 0x%x origin 0x%x", result, error_origin);
        }
    }

    return WALLET_NO_ERROR;
}

/** Invokes a command in the Trusted Application to write the current wallet
  * record.
  * \param address The address in non-volatile memory to write to.
  * \return See #WalletErrors.
  */
WalletErrors writeCurrentWalletRecordTZ(uint32_t address)
{
    TEEC_Result result;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].value.a    -> Address to write the current wallet record.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].value.a = (uint32_t)address;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_WRITE_CURRENT_WALLET,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_WRITE_CURRENT_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)WALLET_WRITE_ERROR);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_WRITE_CURRENT_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
        }

        return WALLET_WRITE_ERROR;
    }

    return WALLET_NO_ERROR;
}

/** Invokes a command in the Trusted Application to derive an encryption
  * key and begin using it.
  * \param uuid Byte array containing the wallet UUID. This must be
  *             exactly #UUID_LENGTH bytes long.
  * \param password Password to use in key derivation.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  */
void deriveAndSetEncryptionKeyTZ(const uint8_t *uuid, const uint8_t *password, const unsigned int password_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].memref.buffer -> UUID.
     * [IN]  params[0].memref.size   -> Length of the UUID.
     * [IN]  params[1].memref.buffer -> Password.
     * [IN]  params[1].memref.size   -> Length of the password.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)uuid;
    operation.params[0].tmpref.size = (size_t)UUID_LENGTH;
    operation.params[1].tmpref.buffer = (uint8_t*)password;
    operation.params[1].tmpref.size = (size_t)password_length;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_DERIVE_AND_SET_ENCRYPTION_KEY,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
    {
        fprintf(stderr, "TEEC_InvokeCommand for CMD_DERIVE_AND_SET_ENCRYPTION_KEY failed with code 0x%x origin 0x%x\n", result, error_origin);
        fatalError();
    }
}

/** Invokes a command in the Trusted Application to get the number of addresses.
  * \return The current number of addresses on success, or 0 if an error
  *         occurred. Use walletGetLastError() to get more detail about
  *         an error.
  */
uint32_t getNumAddressesTZ(void)
{
    TEEC_Result result;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Operation setup */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT]  params[0].value.a  -> Number of addresses.
     * [OUT]  params[0].value.b  -> Wallet last error.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GET_NUM_ADDRESSES,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_NUM_ADDRESSES failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[0].value.b);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_GET_NUM_ADDRESSES failed with code 0x%x origin 0x%x", result, error_origin);
        }
    }

    /* Set the wallet last error */
    last_error = (WalletErrors)(operation.params[0].value.b);

    return operation.params[0].value.a;
}

#ifdef TESTING

/** Invokes a command in the Trusted Application to given an address handle,
  * use the deterministic private key generator to generate the private key
  * associated with that address handle. This function is not really
  * needed for the correct functioning of the wallet it is and should ONLY BE
  * USED for testing purposes.
  * \param out The private key will be written here (if everything goes well).
  *            This must be a byte array with space for 32 bytes.
  * \param ah The address handle to obtain the private key of.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getPrivateKeyTestTZ(uint8_t *out, AddressHandle ah)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> The private key will be written here.
     * [OUT] params[0].memref.size   -> Size of the key.
     * [IN]  params[1].value.a       -> Address handle.
     * [OUT] params[1].value.b       -> WalletErros return.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)out;
    operation.params[0].tmpref.size = (size_t)32;
    operation.params[1].value.a = (uint32_t)ah;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GET_PRIVATE_KEY_TEST,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_PRIVATE_KEY_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[1].value.b);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_GET_PRIVATE_KEY_TEST failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    /* Set the wallet last error */
    last_error = (WalletErrors)(operation.params[1].value.b);

    return last_error;
}

#endif

/** Invokes a command in the Trusted Application to get the address and the
  * public key.
  * \param out_address The address will be written here (if everything
  *                    goes well). This must be a byte array with space for
  *                    20 bytes.
  * \param out_public_key The public key corresponding to the address will
  *                       be written here (if everything goes well).
  * \param ah The address handle to obtain the address/public key of.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getAddressAndPublicKeyTZ(uint8_t *out_address, PointAffine *out_public_key, AddressHandle ah)
{
    TEEC_Operation operation;
    TEEC_Result result = TEEC_SUCCESS;
    uint32_t error_origin;
    uint8_t buffer[32];

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Buffer with the address hashed with sha256.
     * [OUT] params[0].memref.size   -> Size of the buffer.
     * [OUT] params[1].memref.buffer -> Buffer to write the public key.
     * [OUT] params[1].memref.size   -> Size of the buffer.
     * [IN]  params[2].value.a       -> Address handle.
     * [OUT] params[2].value.b       -> WalletErrors return.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)buffer;
    operation.params[0].tmpref.size = sizeof(buffer);
    operation.params[1].tmpref.buffer = (PointAffine*)out_public_key;
    operation.params[1].tmpref.size = sizeof(PointAffine);
    operation.params[2].value.a = (uint32_t)ah;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GET_ADDRESS_AND_PUB_KEY,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_ADDRESS_AND_PUB_KEY failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[2].value.b);
            #endif

            goto cleanup1;
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_GET_ADDRESS_AND_PUB_KEY failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    memcpy(out_address, buffer, 20);

    /* Resource cleanup */
    cleanup1:
        last_error = (WalletErrors)(operation.params[2].value.b);
        return last_error;
}

/** Invokes a command in the Trusted Application to get the master public key of
  * the currently loaded wallet. Every public key (and address) in a wallet can
  * be derived from the master public key and chain code. However, even with
  * possession of the master public key, all private keys are still secret.
  * \param out_public_key The master public key will be written here.
  * \param out_chain_code The chain code will be written here. This must be a
  *                       byte array with space for 32 bytes.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getMasterPublicKeyTZ(PointAffine *out_public_key, uint8_t *out_chain_code)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Buffer to write the public key.
     * [OUT] params[0].memref.size   -> Size of the buffer.
     * [OUT] params[1].memref.buffer -> Buffer to write the chain code.
     * [OUT] params[1].memref.size   -> Size of the buffer.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (PointAffine*)out_public_key;
    operation.params[0].tmpref.size = sizeof(PointAffine);
    operation.params[1].tmpref.buffer = (uint8_t*)out_chain_code;
    operation.params[1].tmpref.size = (size_t)32;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GET_MASTER_PUB_KEY,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_MASTER_PUB_KEY failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)WALLET_NOT_LOADED);
            #endif

            last_error = WALLET_NOT_LOADED;

            goto cleanup1;
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_GET_MASTER_PUB_KEY failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    /* Set the wallet last error */
    last_error = WALLET_NO_ERROR;

    cleanup1:
        return last_error;
}

/** Invokes a command in the Trusted Application to change the encryption key of
  * a wallet.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeEncryptionKeyTZ(const uint8_t *password, const unsigned int password_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup the operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].memref.buffer -> Password.
     * [IN]  params[0].memref.size   -> Length of the password.
     * [OUT] params[1].value.a       -> Wallet last error.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)password;
    operation.params[0].tmpref.size = (size_t)password_length;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_CHANGE_ENCRYPTION_KEY,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_CHANGE_ENCRYPTION_KEY failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[1].value.a);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_CHANGE_ENCRYPTION_KEY failed with code 0x%x origin 0x%x", result, error_origin);
        }
    }

    /* Set the las wallet error */
    last_error = (WalletErrors)(operation.params[1].value.a);

    return last_error;
}

/**
  * Invokes a command in the Trusted Application toLoad contents of non-volatile
  * memory into a #WalletRecord structure.
  * \param wallet_record Where to load the wallet record into.
  * \param address The address in non-volatile memory to read from.
  * \return See #WalletErrors.
  */
WalletErrors readWalletRecordTZ(WalletRecord * wallet_record, uint32_t address)
{
    TEEC_Result result;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Structure to write the wallet record read.
     * [OUT] params[0].memref.size   -> Size of the wallet record to be read.
     * [IN]  params[1].value.a       -> Address to read the wallet record from.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (WalletRecord*)wallet_record;
    operation.params[0].tmpref.size = sizeof(*wallet_record);
    operation.params[1].value.a = (uint32_t)address;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_READ_WALLET_RECORD,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_FORMAT)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_READ_WALLET_RECORD failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)WALLET_INVALID_OPERATION);
            #endif

            return WALLET_INVALID_OPERATION;
        }
        else if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_READ_WALLET_RECORD failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)WALLET_READ_ERROR);
            #endif

            return WALLET_READ_ERROR;
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_READ_WALLET_RECORD failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    return WALLET_NO_ERROR;
}

/** Invokes a command in the Trusted Application to initialize the wallet.
  * \param wallet_spec The wallet number of the wallet to load.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors initWalletTZ(uint32_t wallet_spec, const uint8_t *password, const unsigned int password_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].memref.buffer -> Password.
     * [IN]  params[0].memref.size   -> Length of the password.
     * [IN]  params[1].value.a       -> Wallet specification number.
     * [OUT] params[1].value.b       -> Wallet last error.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_INOUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)password;
    operation.params[0].tmpref.size = (size_t)password_length;
    operation.params[1].value.a = wallet_spec;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_INIT_WALLET,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_FORMAT)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_INIT_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[1].value.b);
            #endif
        }
        else if (result == TEEC_ERROR_BAD_STATE)
        {
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_INIT_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[1].value.b);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_INIT_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    /* Set the last wallet error */
    last_error = (WalletErrors)(operation.params[1].value.b);

    return last_error;
}

/** Invokes a command in the Trusted Application to uninitiate the wallet.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors uninitWalletTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    uint32_t error_origin;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_UNINIT_WALLET,
                    NULL,
                    &error_origin);

    /*
     * If the result is not TEEC_SUCCESS something went wrong that wasn't
     * predicted
     */
    if(result != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand for CMD_UNINIT_WALLET failed with code 0x%x origin 0x%x", result, error_origin);

    /* Set the last wallet error */
    last_error = WALLET_NO_ERROR;

    return last_error;
}

/** Invokes a command in the Trusted Application to get the wallet information.
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
WalletErrors getWalletInfoTZ(uint32_t * out_version, uint8_t * out_name, uint8_t * out_uuid, uint32_t wallet_spec)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].value.a       -> Version.
     * [IN]  params[0].value.b       -> Wallet number specification.
     * [OUT] params[1].memref.buffer -> Name.
     * [OUT] params[1].memref.size   -> Size of Name.
     * [OUT] params[2].memref.buffer -> UUID.
     * [OUT] params[2].memref.size   -> Size of UUID.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_INOUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_NONE);

    /* Define the parameters */
    operation.params[0].value.b = wallet_spec;
    operation.params[1].tmpref.buffer = (uint8_t*)out_name;
    operation.params[1].tmpref.size = (size_t)NAME_LENGTH;
    operation.params[2].tmpref.buffer = (uint8_t*)out_uuid;
    operation.params[2].tmpref.size = (size_t)UUID_LENGTH;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GET_WALLET_INFO,
                    &operation,
                    &error_origin);

    if(result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_FORMAT)
        {
            /* Returned by the readWalletRecord function implemented at the TA */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_WALLET_INFO failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)WALLET_INVALID_OPERATION);
            #endif

            return WALLET_INVALID_OPERATION;
        }
        else if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_WALLET_INFO failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)WALLET_READ_ERROR);
            #endif

            return WALLET_READ_ERROR;
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_GET_WALLET_INFO failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    /* Set the received version from TA */
    *out_version = (uint32_t)(operation.params[0].value.a);

    return WALLET_NO_ERROR;
}

/** Invokes a command in the Trusted Application to change the name of the wallet.
  * \param new_name This should point to #NAME_LENGTH bytes (padded with
  *                 spaces if necessary) containing the new desired name of
  *                 the wallet.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeWalletNameTZ(uint8_t * new_name)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].memref.buffer -> New name
     * [IN]  params[0].memref.size   -> Size of New name.
     * [OUT] params[1].value.a       -> WalletError;
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_VALUE_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)new_name;
    operation.params[0].tmpref.size = (size_t)NAME_LENGTH;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_CHANGE_WALLET_NAME,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_CHANGE_WALLET_NAME failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[1].value.b);
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_CHANGE_WALLET_NAME failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    /* Set the wallet last error */
    last_error = (WalletErrors)(operation.params[1].value.a);

    return last_error;
}

/** Invokes a command in the Trusted Application to create a new wallet.
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
WalletErrors newWalletTZ(uint32_t wallet_spec, uint8_t *name, bool use_seed, uint8_t *seed, bool make_hidden, const uint8_t *password, const unsigned int password_length)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;
    newWalletHelper new_wallet_helper;

    /* Setup the operation */
    memset(&operation, 0, sizeof(operation));

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
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INPUT,
                                TEEC_MEMREF_TEMP_INOUT);

    /* Setup the parameters */
    operation.params[0].tmpref.buffer = (uint8_t*)name;
    operation.params[0].tmpref.size = (size_t)NAME_LENGTH;

    if (use_seed == false)
    {
        operation.params[1].tmpref.buffer = (uint8_t*)NULL;
        operation.params[1].tmpref.size = (size_t)0;
    }
    else
    {
        operation.params[1].tmpref.buffer = (uint8_t*)seed;
        operation.params[1].tmpref.size = (size_t)SEED_LENGTH;
    }

    if(password == NULL)
    {
        operation.params[2].tmpref.buffer = (uint8_t*)NULL;
        operation.params[2].tmpref.size = (size_t)0;
    }
    else
    {
        operation.params[2].tmpref.buffer = (uint8_t*)password;
        operation.params[2].tmpref.size = (size_t)password_length;
    }

    new_wallet_helper.use_seed = use_seed;
    new_wallet_helper.make_hidden = make_hidden;
    new_wallet_helper.wallet_spec = wallet_spec;

    /*
     * In the newWallet function it is needed some buffers with random bytes
     * but to avoid passing the huge amount of code relative to the its
     * generation the buffers are created in the Client Application and passed
     * to the Trusted Application
     */
    if (!make_hidden)
    {
        if (getRandom256(new_wallet_helper.random_buffer_0))
        {
            last_error = WALLET_RNG_FAILURE;
            goto cleanup1;
        }
    }

    if (getRandom256(new_wallet_helper.random_buffer_1))
    {
        last_error = WALLET_RNG_FAILURE;
        goto cleanup1;
    }

    if(!use_seed)
    {
        if (getRandom256(new_wallet_helper.random_buffer_2))
        {
            last_error = WALLET_RNG_FAILURE;
            goto cleanup1;
        }

        if (getRandom256(new_wallet_helper.random_buffer_3))
        {
            last_error = WALLET_RNG_FAILURE;
            goto cleanup1;
        }
    }

    operation.params[3].tmpref.buffer = (newWalletHelper*)&new_wallet_helper;
    operation.params[3].tmpref.size = sizeof(newWalletHelper);

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_NEW_WALLET,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_FORMAT)
        {
            /* Returned by the readWalletRecord function implemented at the TA */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_NEW_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)(new_wallet_helper.wallet_error));
            #endif
        }
        else if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_NEW_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", (uint32_t)(new_wallet_helper.wallet_error));
            #endif
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_NEW_WALLET failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    /* Set the last wallet error */
    last_error = new_wallet_helper.wallet_error;

    /* Resource cleanup */
    cleanup1:
        return last_error;
}

/** Invokes a command in the Trusted Application to get the seed f the current
  * loaded wallet.
  * \param seed Output buffer that will have the seed. It must have at least
  *             #SEED_LENGTH.
  * \param do_encryption True for encrypted seed, false for unencrypted seed.
  * \return true on success, false in case of error.
  */
bool getSeedTZ(uint8_t * seed, bool do_encryption)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [IN]  params[0].value.a       -> Boolean to indicate if is to encrypt or
     *                                  not the seed.
     * [OUT] params[0].value.b       -> WalletErrors return (of wallet_loaded).
     * [OUT] params[1].memref.buffer -> Buffer to write the seed.
     * [OUT] params[1].memref.size   -> Size of the buffer.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_INOUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_NONE,
                                TEEC_NONE);

    operation.params[0].value.a = (uint32_t)do_encryption;
    operation.params[1].tmpref.buffer = (uint8_t*)seed;
    operation.params[1].tmpref.size = (size_t)SEED_LENGTH;

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_GET_SEED,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_GET_SEED failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[0].value.b);
            #endif

            /* Set the wallet last error */
            last_error = (WalletErrors)(operation.params[0].value.b);

            return false;
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_GET_SEED failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    return true;
}

/** Invokes a command in the Trusted Application to create a new address.
  * \param out_address The new address will be written here (if everything
  *                    goes well). This must be a byte array with space for
  *                    20 bytes.
  * \param out_public_key The public key corresponding to the new address will
  *                       be written here (if everything goes well).
  * \return The address handle of the new address on success,
  *         or #BAD_ADDRESS_HANDLE if an error occurred.
  *         Use walletGetLastError() to get more detail about an error.
  */
AddressHandle makeNewAddressTZ(uint8_t *out_address, PointAffine *out_public_key)
{
    AddressHandle ah_result;
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation;
    uint32_t error_origin;
    uint8_t buffer[32];

    /* Setup operation */
    memset(&operation, 0, sizeof(operation));

    /*
     * Expected:
     * [OUT] params[0].memref.buffer -> Buffer to write the address.
     * [OUT] params[0].memref.size   -> Size of the buffer.
     * [OUT] params[1].memref.buffer -> Buffer to write the public key.
     * [OUT] params[1].memref.size   -> Size of the buffer.
     * [OUT] params[2].value.a       -> AddressHandle return.
     * [OUT] params[2].value.b       -> WalletErros return.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_MEMREF_TEMP_OUTPUT,
                                TEEC_VALUE_OUTPUT,
                                TEEC_NONE);

    operation.params[0].tmpref.buffer = (uint8_t*)buffer;
    operation.params[0].tmpref.size = sizeof(buffer);
    operation.params[1].tmpref.buffer = (PointAffine*)out_public_key;
    operation.params[1].tmpref.size = sizeof(PointAffine);

    /* Invoke the command */
    result = TEEC_InvokeCommand(
                    &session,
                    CMD_MAKE_NEW_ADDRESS,
                    &operation,
                    &error_origin);

    if (result != TEEC_SUCCESS)
    {
        if (result == TEEC_ERROR_BAD_STATE)
        {
            /* When an error occurs but it was a possible and allowed one */
            #ifdef DEBUG
            fprintf(stderr, "TEEC_InvokeCommand for CMD_MAKE_NEW_ADDRESS failed with code 0x%x origin 0x%x\n", result, error_origin);
            fprintf(stderr, "WalletErrors: %d\n", operation.params[2].value.b);
            #endif

            goto cleanup1;
        }
        else
        {
            /*
             * This case happens when the parameters are wrongly defined or
             * when other more dangerous error happened in this case the safest
             * solution is to exit the program
             */
            errx(1, "TEEC_InvokeCommand for CMD_MAKE_NEW_ADDRESS failed with code 0x%x origin 0x%x\n", result, error_origin);
        }
    }

    memcpy(out_address, buffer, 20);

    /* Resources cleanup */
    cleanup1:
        ah_result = (AddressHandle)(operation.params[2].value.a);
        last_error = (WalletErrors)(operation.params[2].value.b);
        return ah_result;
}

#ifdef TESTING

/** Dummy function that does nothing. It is currently used just to measure the
  * time of an CA function call.
  */
void CAFunctionCall(void)
{
}

/** Invokes a command in the Trusted Application to do nothing. It is currently
  * used just to measure the time of an TA function call.
  */
bool TAFunctionCall(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    uint32_t error_origin;

    if (is_test_performance)
    {
        startTest("Measuring time of TA function call");

        result = TEEC_InvokeCommand(
                        &session,
                        CMD_TEST_CALL,
                        NULL,
                        &error_origin);

        finishTest();

        if(result != TEEC_SUCCESS)
        {
            fprintf(stderr, "TEEC_InvokeCommand for CMD_TEST_CALL failed with code 0x%x origin 0x%x\n", result, error_origin);
            return false;
        }
    }

    return true;
}

#endif
