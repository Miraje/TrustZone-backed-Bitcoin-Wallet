/** \file hmac_drbg.h
  *
  * \brief Describes functions and types exported and used by hmac_drbg.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef HMAC_DRBG_H_INCLUDED
#define HMAC_DRBG_H_INCLUDED

#include "common.h"

/** Internal state of a HMAC_DRBG instance. The internal state can be
  * instantiated via. drbgInstantiate(), updated via. drbgReseed() and
  * used for bit generation via. drbgGenerate(). */
typedef struct HMACDRBGStateStruct
{
	/** This is sometimes called "K" in NIST SP 800-90A. It is usually used as
	  * the key in HMAC invocations. */
	uint8_t key[32];
	/** This is sometimes called "V" in NIST SP 800-90A This is usually used as
	  * the message/value in HMAC invocations. */
	uint8_t v[32];
} HMACDRBGState;

#endif // #ifndef HMAC_DRBG_H_INCLUDED
