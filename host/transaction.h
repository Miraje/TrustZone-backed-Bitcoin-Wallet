/** \file
  *
  * \brief Describes functions and types exported by transaction.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef TRANSACTION_H_INCLUDED
#define TRANSACTION_H_INCLUDED

#include "common.h"
#include "bignum256.h"

/** Maximum size (in number of bytes) of the DER format ECDSA signature which
  * signTransaction() generates. */
#define MAX_SIGNATURE_LENGTH	73

/** The maximum size of a transaction (in bytes) which parseTransaction()
  * is prepared to handle. */
#define MAX_TRANSACTION_SIZE    2000000

/** The maximum number of inputs that the transaction parser is prepared
  * to handle. This should be small enough that a transaction with the
  * maximum number of inputs is still less than #MAX_TRANSACTION_SIZE bytes in
  * size.
  * \warning This must be < 65536, otherwise an integer overflow may occur.
  */
#define MAX_INPUTS				5000

/** The maximum number of outputs that the transaction parser is prepared
  * to handle. This should be small enough that a transaction with the
  * maximum number of outputs is still less than #MAX_TRANSACTION_SIZE bytes
  * in size.
  * \warning This must be < 65536, otherwise an integer overflow may occur.
  */
#define MAX_OUTPUTS				2000

/**
 * \defgroup DEROffsets Offsets for DER signature encapsulation.
 *
 * @{
 */
/** Initial offset of r in signature. It's 4 because 4 bytes are needed for
  * the SEQUENCE/length and INTEGER/length bytes. */
#define R_OFFSET	           4
/** Initial offset of s in signature. It's 39 because: r is initially 33
  * bytes long, and 2 bytes are needed for INTEGER/length. 4 + 33 + 2 = 39. */
#define S_OFFSET	           39
/**@}*/

/** The maximum amount that can appear in an output, stored as a little-endian
  * multi-precision integer. This represents 21 million BTC. */
static const uint8_t max_money[] = {
0x00, 0x40, 0x07, 0x5A, 0xF0, 0x75, 0x07, 0x00};

/** Return values for parseTransaction(). */
typedef enum TransactionErrorsEnum
{
	/** No error actually occurred. */
	TRANSACTION_NO_ERROR				=	0,
	/** Format of transaction is unknown or invalid. */
	TRANSACTION_INVALID_FORMAT			=	1,
	/** Too many inputs in transaction. */
	TRANSACTION_TOO_MANY_INPUTS			=	2,
	/** Too many outputs in transaction. */
	TRANSACTION_TOO_MANY_OUTPUTS		=	3,
	/** Transaction's size (in bytes) is too large. */
	TRANSACTION_TOO_LARGE				=	4,
	/** Transaction not recognised (i.e. non-standard). */
	TRANSACTION_NON_STANDARD			=	5,
	/** Output amount too high in transaction. This can also be returned if
	  * the calculated transaction fee is negative. */
	TRANSACTION_INVALID_AMOUNT			=	7,
	/** Reference to an inner transaction is invalid. */
	TRANSACTION_INVALID_REFERENCE		=	8
} TransactionErrors;

TransactionErrors parseTransaction(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length);
uint8_t encapsulateSignature(uint8_t *signature, BigNum256 r, BigNum256 s);
void signTransaction(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, BigNum256 private_key);
WalletErrors signTransaction2(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, AddressHandle ah);
bool isEndOfTransactionData(void);

#endif /* #ifndef TRANSACTION_H_INCLUDED */
