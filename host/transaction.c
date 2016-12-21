/** \file
  *
  * \brief Contains functions specific to Bitcoin transactions.
  *
  * There are two main things which are dealt with in this file.
  * The first is the parsing of Bitcoin transactions. During the parsing
  * process, useful stuff (such as output addresses and amounts) is
  * extracted. See the code of parseTransactionInternal() for the guts.
  *
  * The second is the generation of Bitcoin-compatible signatures. Bitcoin
  * uses OpenSSL to generate signatures, and OpenSSL insists on encapsulating
  * the "r" and "s" values (see ecdsaSign()) in DER format. See the code of
  * signTransaction() for the guts.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "baseconv.h"
#include "bignum256.h"
#include "common.h"
#include "ecdsa.h"
#include "endian.h"
#include "extern.h"
#include "stream_comm.h"
#include "transaction.h"
#include "tz_functions.h"
#include "wallet.h"

#include <stdlib.h>

/** If this is false, then as the transaction contents are read from the
  * stream device, they will not be included in the calculation of the
  * transaction hash or the signature hash. If this is true, then they
  * will be included. This is used to stop #sig_hash_hs_ptr
  * and #transaction_hash_hs_ptr from being written to if they don't point
  * to a valid hash state. */
static bool hs_ptr_valid;

/** The transaction fee amount, calculated as output amounts subtracted from
  * input amounts. */
static uint8_t transaction_fee_amount[8];

/** Pointer to hash state used to calculate the signature
  * hash (see parseTransaction() for what this is all about).
  * \warning If this does not point to a valid hash state structure, ensure
  *          that #hs_ptr_valid is false to
  *          stop getTransactionBytes() from attempting to dereference this.
  */
//static HashState *sig_hash_hs_ptr;
static uint32_t * sig_hash_hs_ptr;

/** Pointer to hash state used to calculate the transaction
  * hash (see parseTransaction() for what this is all about).
  * \warning If this does not point to a valid hash state structure, ensure
  *          that #hs_ptr_valid is false to
  *          stop getTransactionBytes() from attempting to dereference this.
  */
//static HashState *transaction_hash_hs_ptr;
static uint32_t * transaction_hash_hs_ptr;

/** If this is true, then as the transaction contents are read from the
  * stream device, they will not be included in the calculation of the
  * transaction hash (see parseTransaction() for what this is all about).
  * If this is false, then they will be included. */
static bool suppress_transaction_hash;

/** Get transaction data by reading from the stream device, checking that
  * the read operation won't go beyond the end of the transaction data.
  *
  * Since all transaction data is read using this function, the updating
  * of #sig_hash_hs_ptr and #transaction_hash_hs_ptr is also done.
  * \param buffer An array of bytes which will be filled with the transaction
  *               data (if everything goes well). It must have space for
  *               length bytes.
  * \param length The number of bytes to read from the stream device.
  * \return false on success, true if a stream read error occurred or if the
  *         read would go beyond the end of the transaction data.
  */
static bool getTransactionBytes(uint8_t *buffer, uint8_t length)
{
    // uint8_t i;
    // uint8_t one_byte;

    if (transaction_data_index > (0xffffffff - (uint32_t)length))
    {
        /*
         * transaction_data_index + (uint32_t)length will overflow. Since the
         * transaction_length <= 0xffffffff, this implies that the read will
         * go past the end of the transaction.
         */
         return true;
    }

    if (transaction_data_index + (uint32_t)length > transaction_length)
        return true;    /* Trying to read past the end of the transaction */
    else
    {
        // for (i = 0; i < length; i++)
        // {
        //     one_byte = streamGetOneByte();
        //     buffer[i] = one_byte;

        //     if (hs_ptr_valid)
        //     {
        //         //sha256WriteByte(sig_hash_hs_ptr, one_byte);
        //         sha256Write2TZ(&one_byte, (uint32_t)1);

        //         if (!suppress_transaction_hash)
        //         {
        //             //sha256WriteByte(transaction_hash_hs_ptr, one_byte);
        //             sha256Write3TZ(&one_byte, (uint32_t)1);
        //         }
        //     }

        //     transaction_data_index++;
        // }

        // for (i = 0; i < length; i++)
        // {
        //     one_byte = streamGetOneByte();
        //     buffer[i] = one_byte;
        // }

        // startTest("new get bytes");

        streamGetBytes(buffer, length);

        transaction_data_index += (uint32_t)length;

        if (hs_ptr_valid)
        {
            //sha256WriteByte(sig_hash_hs_ptr, one_byte);
            sha256WriteTZ(buffer, (uint32_t)length, 2);

            if (!suppress_transaction_hash)
            {
                //sha256WriteByte(transaction_hash_hs_ptr, one_byte);
                sha256WriteTZ(buffer, (uint32_t)length, 3);
            }
        }

        // finishTest();

        return false;
    }
}

/** Parse a variable-sized integer within a transaction. Variable sized
  * integers are commonly used to represent counts or sizes in Bitcoin
  * transactions.
  * This only supports unsigned variable-sized integers up to a maximum
  * value of 2 ^ 32 - 1.
  * \param out The value of the integer will be written to here.
  * \return false on success, true to indicate an error occurred (unexpected
  *         end of transaction data or the value of the integer is too large).
  */
static bool getVarInt(uint32_t *out)
{
    uint8_t temp[4];

    if (getTransactionBytes(temp, 1))
        return true;    /* Unexpected end of transaction data */

    if (temp[0] < 0xfd)
        *out = temp[0];
    else if (temp[0] == 0xfd)
    {
        if (getTransactionBytes(temp, 2))
            return true;    /* Unexpected end of transaction data */

        *out = (uint32_t)(temp[0]) | ((uint32_t)(temp[1]) << 8);
    }
    else if (temp[0] == 0xfe)
    {
        if (getTransactionBytes(temp, 4))
            return true;    /* Unexpected end of transaction data */

        *out = readU32LittleEndian(temp);
    }
    else
        return true;    /* Varint is too large */

    return false;   /* Success */
}

/** Checks whether the transaction parser is at the end of the transaction
  * data.
  * \return false if not at the end of the transaction data, true if at the
  *         end of the transaction data.
  */
bool isEndOfTransactionData(void)
{
    if (transaction_data_index >= transaction_length)
        return true;
    else
        return false;
}

/** See comments for parseTransaction() for description of what this does
  * and return values. However, the guts of the transaction parser are in
  * the code to this function.
  *
  * This is called once for each input transaction and once for the spending
  * transaction.
  * \param sig_hash See parseTransaction().
  * \param transaction_hash See parseTransaction().
  * \param is_ref_out On success, this will be written with true
  *                   if the transaction parser parsed an input (i.e.
  *                   referenced by input of spending) transaction. This will
  *                   be written with false if the transaction parser parsed
  *                   the main (i.e. spending) transaction.
  * \param ref_compare_hs Reference compare hash. This is used to check that
  *                       the input transactions match the references in the
  *                       main transaction.
  * \return See parseTransaction().
  */
static TransactionErrors parseTransactionInternal(BigNum256 sig_hash, BigNum256 transaction_hash, bool *is_ref_out, uint32_t *ref_compare_hs)
{
    uint8_t temp[32];
    bool is_ref;
    uint32_t output_num_select;
    uint8_t j;
    uint8_t ref_compare_hash[32];
    uint32_t num_inputs;
    uint16_t i;
    uint8_t input_reference_num_buffer[4];
    uint32_t script_length;
    uint32_t k;
    uint32_t num_outputs;
    char text_amount[TEXT_AMOUNT_LENGTH];
    char text_address[TEXT_ADDRESS_LENGTH];
    uint8_t sig_hash_inv[32];

    if (transaction_length > MAX_TRANSACTION_SIZE)
        return TRANSACTION_TOO_LARGE;

    /*
     * Suppress hashing of input stream, otherwise the is_ref byte and output
     * number (which are not part of the transaction data) will be included
     * in the signature/transaction hash.
     */
    hs_ptr_valid = false;

    if (getTransactionBytes(temp, 1))
        return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

    if (temp[0] != 0)
        is_ref = true;
    else
        is_ref = false;

    *is_ref_out = is_ref;

    output_num_select = 0;

    if (is_ref)
    {
        /* Get output number to add to total amount. */
        if (getTransactionBytes(temp, 4))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

        /*
        for (j = 0; j < 4; j++)
            sha256WriteByte(ref_compare_hs, temp[j]);
        */

        sha256WriteTZ(temp, (uint32_t)4, 1);

        output_num_select = readU32LittleEndian(temp);
    }
    else
    {
        /* Generate hash of input transaction references for comparison. */
        /*
        sha256FinishDouble(ref_compare_hs);
        writeHashToByteArray(ref_compare_hash, ref_compare_hs, false);
        sha256Begin(ref_compare_hs);
        */
        sha256FinishDoubleTZ(ref_compare_hs, (uint32_t)32, 1);
        writeHashToByteArrayTZ(ref_compare_hash, ref_compare_hs, false);
        sha256BeginTZ(1);
    }

    //sha256Begin(sig_hash_hs_ptr);
    //sha256Begin(transaction_hash_hs_ptr);

    sha256BeginTZ(2);
    sha256BeginTZ(3);

    hs_ptr_valid = true;
    suppress_transaction_hash = false;

    /* Check the version. */
    if (getTransactionBytes(temp, 4))
        return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

    if (readU32LittleEndian(temp) != 0x00000001)
        return TRANSACTION_NON_STANDARD;    /* Unsupported transaction version */

    /* Get number of inputs. */
    if (getVarInt(&num_inputs))
        return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated or varint too big */

    if (num_inputs == 0)
        return TRANSACTION_INVALID_FORMAT;  /* Invalid transaction */

    if (num_inputs > MAX_INPUTS)
        return TRANSACTION_TOO_MANY_INPUTS; /* Too many inputs */

    /* Process each input. */
    for (i = 0; i < num_inputs; i++)
    {
        /* Get input transaction reference hash. */
        if (getTransactionBytes(temp, 32))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

        /* Get input transaction reference number. */
        if (getTransactionBytes(input_reference_num_buffer, 4))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

        if (!is_ref)
        {
            /*
            for (j = 0; j < 4; j++)
            {
                //sha256WriteByte(ref_compare_hs, input_reference_num_buffer[j]);
                //sha256WriteTZ(&(input_reference_num_buffer[j]), 1);
            }
            */
            sha256WriteTZ(input_reference_num_buffer, (uint32_t)4, 1);

            /*
            for (j = 0; j < 32; j++)
            {
                //sha256WriteByte(ref_compare_hs, temp[j]);
                //sha256WriteTZ(&(temp[j]), 1);
            }
            */
            sha256WriteTZ(temp, (uint32_t)32, 1);
        }

        /*
         * The Bitcoin protocol for signing a transaction involves replacing
         * the corresponding input script with the output script that
         * the input references. This means that the transaction data parsed
         * here will be different depending on which input is being signed
         * for. The transaction hash is supposed to be the same regardless of
         * which input is being signed for, so the calculation of the
         * transaction hash ignores input scripts.
         */
        suppress_transaction_hash = true;

        /* Get input script length. */
        if (getVarInt(&script_length))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated or varint too big */

        /* Skip the script because it's useless here. */
        for (k = 0; k < script_length; k++)
        {
            if (getTransactionBytes(temp, 1))
                return TRANSACTION_INVALID_FORMAT; // transaction truncated
        }

        suppress_transaction_hash = false;

        /*
         * Check sequence. Since locktime is checked below, this check
         * is probably superfluous. But it's better to be safe than sorry.
         */
        if (getTransactionBytes(temp, 4))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

        if (readU32LittleEndian(temp) != 0xFFFFFFFF)
            return TRANSACTION_NON_STANDARD;    /* Replacement not supported */

    } /* End for (i = 0; i < num_inputs; i++) */

    if (!is_ref)
    {
        /* Compare input references with input transactions. */
        //sha256FinishDouble(ref_compare_hs);
        sha256FinishDoubleTZ(ref_compare_hs, (uint32_t)32, 1);

        //writeHashToByteArray(temp, ref_compare_hs, false);
        writeHashToByteArrayTZ(temp, ref_compare_hs, false);

        if (memcmp(temp, ref_compare_hash, 32))
            return TRANSACTION_INVALID_REFERENCE;   /* References don't match input transactions */
    }

    /* Get number of outputs. */
    if (getVarInt(&num_outputs))
        return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated or varint too big */

    if (num_outputs == 0)
        return TRANSACTION_INVALID_FORMAT;  /* Invalid transaction */

    if (num_outputs > MAX_OUTPUTS)
        return TRANSACTION_TOO_MANY_OUTPUTS;    /* Too many outputs */

    if (is_ref)
    {
        if (output_num_select >= num_outputs)
            return TRANSACTION_INVALID_REFERENCE;   /* Bad reference number */
    }

    /* Process each output. */
    for (i = 0; i < num_outputs; i++)
    {
        /* Get output amount. */
        if (getTransactionBytes(temp, 8))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

        if (bigCompareVariableSize(temp, (uint8_t *)max_money, 8) == BIGCMP_GREATER)
            return TRANSACTION_INVALID_AMOUNT;  /* Amount too high */

        if (is_ref)
        {
            if (i == output_num_select)
            {
                if (bigAddVariableSizeNoModulo(transaction_fee_amount, transaction_fee_amount, temp, 8))
                    return TRANSACTION_INVALID_AMOUNT;  /* Overflow occurred (carry occurred) */
            }
        }
        else
        {
            if (bigSubtractVariableSizeNoModulo(transaction_fee_amount, transaction_fee_amount, temp, 8))
                return TRANSACTION_INVALID_AMOUNT;  /* Overflow occurred (borrow occurred) */

            amountToText(text_amount, temp);
        }

        /* Get output script length. */
        if (getVarInt(&script_length))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated or varint too big */

        if (is_ref)
        {
            /*
             * The actual output scripts of input transactions don't need to be parsed (only
             * the amount matters), so skip the script.
             */
            for (k = 0; k < script_length; k++)
            {
                if (getTransactionBytes(temp, 1))
                    return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */
            }
        }
        else
        {
            /* Parsing a spending transaction; output scripts need to be matched to a template. */
            if (script_length == 0x19)
            {
                /*
                 * Expect a standard, pay to public key hash output script.
                 * Look for: OP_DUP, OP_HASH160, (20 bytes of data).
                 */
                if (getTransactionBytes(temp, 3))
                    return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

                if ((temp[0] != 0x76) || (temp[1] != 0xa9) || (temp[2] != 0x14))
                    return TRANSACTION_NON_STANDARD;    /* Nonstandard transaction */

                if (getTransactionBytes(temp, 20))
                    return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

                hashToAddr(text_address, temp, ADDRESS_VERSION_PUBKEY);

                /* Look for: OP_EQUALVERIFY OP_CHECKSIG. */
                if (getTransactionBytes(temp, 2))
                    return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

                if ((temp[0] != 0x88) || (temp[1] != 0xac))
                    return TRANSACTION_NON_STANDARD;    /* Nonstandard transaction */
            }
            else if (script_length == 0x17)
            {
                /*
                 * Expect a standard, pay to script hash output script.
                 * Look for: OP_HASH160, (20 bytes of data).
                 */
                if (getTransactionBytes(temp, 2))
                    return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

                if ((temp[0] != 0xa9) || (temp[1] != 0x14))
                    return TRANSACTION_NON_STANDARD;    /* Nonstandard transaction */

                if (getTransactionBytes(temp, 20))
                    return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

                hashToAddr(text_address, temp, ADDRESS_VERSION_P2SH);

                /* Look for: OP_EQUAL. */
                if (getTransactionBytes(temp, 1))
                    return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

                if (temp[0] != 0x87)
                    return TRANSACTION_NON_STANDARD;    /* Nonstandard transaction */
            }
            else
                return TRANSACTION_NON_STANDARD;    /* Nonstandard transaction */

            if (newOutputSeen(text_amount, text_address))
                return TRANSACTION_TOO_MANY_OUTPUTS;    /* Too many outputs */
        } /* End if (is_ref) */
    } /* End for (i = 0; i < num_outputs; i++) */

    /* Check locktime. */
    if (getTransactionBytes(temp, 4))
        return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

    if (readU32LittleEndian(temp) != 0x00000000)
        return TRANSACTION_NON_STANDARD;    /* Replacement not supported */

    if (!is_ref)
    {
        /* Check hashtype. */
        if (getTransactionBytes(temp, 4))
            return TRANSACTION_INVALID_FORMAT;  /* Transaction truncated */

        if (readU32LittleEndian(temp) != 0x00000001)
            return TRANSACTION_NON_STANDARD;    /* Nonstandard transaction */

        /* Is there junk at the end of the transaction data? */
        if (!isEndOfTransactionData())
            return TRANSACTION_INVALID_FORMAT;  /* Junk at end of transaction data */

        if (!bigIsZeroVariableSize(transaction_fee_amount, sizeof(transaction_fee_amount)))
        {
            amountToText(text_amount, transaction_fee_amount);
            setTransactionFee(text_amount);
        }
    }

    //sha256FinishDouble(sig_hash_hs_ptr);
    sha256FinishDoubleTZ(sig_hash_hs_ptr, (uint32_t)32, 2);

    /*
     * The signature hash is written in a little-endian format because it
     * is used as a little-endian multi-precision integer in
     * signTransaction().
     */
    /*
    writeHashToByteArray(sig_hash, sig_hash_hs_ptr, false);
    sha256FinishDouble(transaction_hash_hs_ptr);
    writeHashToByteArray(transaction_hash, transaction_hash_hs_ptr, false);
    */
    writeHashToByteArrayTZ(sig_hash, sig_hash_hs_ptr, false);
    sha256FinishDoubleTZ(transaction_hash_hs_ptr, (uint32_t)32, 3);
    writeHashToByteArrayTZ(transaction_hash, transaction_hash_hs_ptr, false);

    if (is_ref)
    {
        /*
         * Why backwards? Because Bitcoin serialises the input reference
         * hashes that way.
         */
        for (j = 32; j--; )
        {
            //sha256WriteByte(ref_compare_hs, sig_hash[j]);
            //sha256WriteTZ(&(sig_hash[j]), (uint32_t)1);
            sig_hash_inv[31-j] = sig_hash[j];
        }

        sha256WriteTZ(sig_hash_inv, (uint32_t)32, 1);

        // for (j = 32; j--; )
        // {
        //     //sha256WriteByte(ref_compare_hs, sig_hash[j]);
        //     sha256WriteTZ(&(sig_hash[j]), (uint32_t)1);
        // }
    }

    return TRANSACTION_NO_ERROR;
}

/** Parse a Bitcoin transaction, extracting the output amounts/addresses,
  * validating the transaction (ensuring that it is "standard") and computing
  * a double SHA-256 hash of the transaction. This double SHA-256 hash is the
  * "signature hash" because it is the hash which is passed on to the signing
  * function signTransaction().
  *
  * The Bitcoin protocol for signing a transaction involves replacing
  * the corresponding input script with the output script that
  * the input references. This means that for a transaction with n
  * inputs, there will be n different signature hashes - one for each input.
  * Requiring the user to approve a transaction n times would be very
  * annoying, so there needs to be a way to determine whether a bunch of
  * transactions are actually "the same".
  * So in addition to the signature hash, a "transaction hash" will be
  * computed. The transaction hash is just like the signature hash, except
  * input scripts are not included.
  *
  * This expects the input stream to contain many concatenated transactions;
  * it should contain each input transaction (of the spending transaction)
  * followed by the spending transaction. This is necessary
  * to calculate the transaction fee. A transaction does directly contain the
  * output amounts, but not the input amounts. The only way to get input
  * amounts is to look at the output amounts of the transactions the inputs
  * refer to.
  *
  * \param sig_hash The signature hash will be written here (if everything
  *                 goes well), as a 32 byte little-endian multi-precision
  *                 number.
  * \param transaction_hash The transaction hash will be written here (if
  *                         everything goes well), as a 32 byte little-endian
  *                         multi-precision number.
  * \param length The total length of the transaction. If no stream read
  *               errors occured, then exactly length bytes will be read from
  *               the stream, even if the transaction was not parsed
  *               correctly.
  * \return One of the values in #TransactionErrorsEnum.
  */
TransactionErrors parseTransaction(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length)
{
    //HashState sig_hash_hs;
    uint32_t sig_hash_hs[8];
    //HashState transaction_hash_hs;
    uint32_t transaction_hash_hs[8];
    //HashState ref_compare_hs;
    uint32_t ref_compare_hs[8];
    TransactionErrors response;
    bool is_ref;
    uint8_t junk;

    hs_ptr_valid = false;
    transaction_data_index = 0;
    transaction_length = length;

    memset(transaction_fee_amount, 0, sizeof(transaction_fee_amount));

    sig_hash_hs_ptr = sig_hash_hs;
    transaction_hash_hs_ptr = transaction_hash_hs;

    //sha256Begin(&ref_compare_hs);

    sha256BeginTZ(1);

    hs_ptr_valid = true;

    do
    {
        response = parseTransactionInternal(sig_hash, transaction_hash, &is_ref, ref_compare_hs);
    } while ((response == TRANSACTION_NO_ERROR) && is_ref);

    hs_ptr_valid = false;

    /* Always try to consume the entire stream. */
    while (!isEndOfTransactionData())
    {
        if (getTransactionBytes(&junk, 1))
            break;
    }

    return response;
}

/** Encapsulate an ECDSA signature in the DER format which OpenSSL uses.
  * This function does not fail.
  * \param signature This must be a byte array with space for at
  *                  least #MAX_SIGNATURE_LENGTH bytes. On exit, the
  *                  encapsulated signature will be written here.
  * \param r The r value of the ECDSA signature. This should be a 32 byte
  *          little-endian multi-precision integer.
  * \param s The s value of the ECDSA signature. This should be a 32 byte
  *          little-endian multi-precision integer.
  * \return The length of the signature, in number of bytes.
  */
uint8_t encapsulateSignature(uint8_t *signature, BigNum256 r, BigNum256 s)
{
    uint8_t sequence_length;
    uint8_t i;

    memcpy(&(signature[R_OFFSET + 1]), r, 32);
    memcpy(&(signature[S_OFFSET + 1]), s, 32);

    /*
     * Place an extra leading zero in front of r and s, just in case their
     * most significant bit is 1.
     * Integers in DER are always 2s-complement signed, but r and s are
     * non-negative. Thus if the most significant bit of r or s is 1,
     * a leading zero must be placed in front of the integer to signify that
     * it is non-negative.
     * If the most significant bit is not 1, the extraneous leading zero will
     * be removed in a check below.
     */
    signature[R_OFFSET] = 0x00;
    signature[S_OFFSET] = 0x00;

    /* Integers in DER are big-endian. */
    swapEndian256(&(signature[R_OFFSET + 1]));
    swapEndian256(&(signature[S_OFFSET + 1]));

    sequence_length = 0x46; /* 2 + 33 + 2 + 33 */
    signature[R_OFFSET - 2] = 0x02; /* INTEGER */
    signature[R_OFFSET - 1] = 0x21; /* length of INTEGER */
    signature[S_OFFSET - 2] = 0x02; /* INTEGER */
    signature[S_OFFSET - 1] = 0x21; /* length of INTEGER */
    signature[S_OFFSET + 33] = 0x01;    /* hashtype */

    /*
     * According to DER, integers should be represented using the shortest
     * possible representation. This implies that leading zeroes should
     * always be removed. The exception to this is that if removing the
     * leading zero would cause the value of the integer to change (eg.
     * positive to negative), the leading zero should remain.
     * Remove unncecessary leading zeroes from s. s is pruned first
     * because pruning r will modify the offset where s begins.
     */
    while ((signature[S_OFFSET] == 0) && ((signature[S_OFFSET + 1] & 0x80) == 0))
    {
        for (i = S_OFFSET; i < 72; i++)
            signature[i] = signature[i + 1];

        sequence_length--;
        signature[S_OFFSET - 1]--;

        if (signature[S_OFFSET - 1] == 1)
            break;
    }

    /* Remove unnecessary leading zeroes from r. */
    while ((signature[R_OFFSET] == 0) && ((signature[R_OFFSET + 1] & 0x80) == 0))
    {
        for (i = R_OFFSET; i < 72; i++)
            signature[i] = signature[i + 1];

        sequence_length--;
        signature[R_OFFSET - 1]--;

        if (signature[R_OFFSET - 1] == 1)
            break;
    }

    signature[0] = 0x30;    /* SEQUENCE */
    signature[1] = sequence_length; /* length of SEQUENCE */

    /* 3 extra bytes: SEQUENCE/length and hashtype */
    return (uint8_t)(sequence_length + 3);
}


/** Sign a transaction. This should be called after the transaction is parsed
  * and a signature hash has been computed. The primary purpose of this
  * function is to call ecdsaSign() and encapsulate the ECDSA signature in
  * the DER format which OpenSSL uses.
  * \param signature The encapsulated signature will be written here. This
  *                  must be a byte array with space for
  *                  at least #MAX_SIGNATURE_LENGTH bytes.
  * \param out_length The length of the signature, in number of bytes, will be
  *                   written here (on success). This length includes the hash
  *                   type byte.
  * \param sig_hash The signature hash of the transaction (see
  *                 parseTransaction()).
  * \param private_key The private key to sign the transaction with. This must
  *                    be a 32 byte little-endian multi-precision integer.
  * \return false on success, or true if an error occurred while trying to
  *         obtain a random number.
  */
void signTransaction(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, BigNum256 private_key)
{
    uint8_t r[32];
    uint8_t s[32];

    *out_length = 0;

    ecdsaSignTestTZ(r, s, sig_hash, private_key);

    *out_length = encapsulateSignature(signature, r, s);
}


WalletErrors signTransaction2(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, AddressHandle ah)
{
    WalletErrors wallet_error = WALLET_NO_ERROR;
    uint8_t r[32];
    uint8_t s[32];

    *out_length = 0;

    wallet_error = ecdsaSignTZ(r, s, sig_hash, ah);

    if (wallet_error != WALLET_NO_ERROR)
      return wallet_error;

    *out_length = encapsulateSignature(signature, r, s);

    return wallet_error;
}