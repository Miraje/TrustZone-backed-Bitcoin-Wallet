/** \file
  *
  * \brief Deals with random and pseudo-random number generation.
  *
  * At the moment this covers whitening of random inputs (getRandom256()) and
  * deterministic private key generation (generateDeterministic256()).
  *
  * The suggestion to use a persistent entropy pool, and much of the code
  * associated with the entropy pool, are attributed to Peter Todd (retep).
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "bignum256.h"
#include "common.h"
#include "ecdsa.h"
#include "endian.h"
#include "extern.h"
#include "hwinterface.h"
#include "prandom.h"
#include "storage_common.h"
#include "tz_functions.h"

#include <stdio.h>
#include <stdlib.h>

/** Use a combination of cryptographic primitives to deterministically
  * generate a new public key.
  *
  * The generator uses the algorithm described in
  * https://en.bitcoin.it/wiki/BIP_0032, accessed 12-November-2012 under the
  * "Specification" header. The generator generates uncompressed keys.
  *
  * \param out_public_key The generated public key will be written here.
  * \param in_parent_public_key The parent public key, referred to as K_par in
  *                             the article above.
  * \param chain_code Should point to a byte array of length 32 containing
  *                   the BIP 0032 chain code.
  * \param num A counter which determines which number the pseudo-random
  *            number generator will output.
  */
void generateDeterministicPublicKey(PointAffine *out_public_key, PointAffine *in_parent_public_key, const uint8_t *chain_code, const uint32_t num)
{
    generateDeterministicPublicKeyTestTZ(out_public_key, in_parent_public_key,  chain_code,  num);
}

/** Clear the parent public key cache (see #parent_private_key). This should
  * be called whenever a wallet is unloaded, so that subsequent calls to
  * generateDeterministic256() don't result in addresses from the old wallet.
  */
void clearParentPublicKeyCache(void)
{
    clearParentPublicKeyCacheTZ();
}

/** Fill buffer with 32 random bytes from a hardware random number generator. As
  * Juno-r2 board does not has a hardware random generator it is used the
  * TEE_GenerateRandom() function provided by OP-TEE and specified by Global
  * Platform in TEE Internal Core API Specification v1.1.
  *
  * It is to notice that the Juno platform does indeed include a
  * "Trusted Entropy Source" which provides a 128-bit random number:
  * http://infocenter.arm.com/help/topic/com.arm.doc.ddi0515f/index.html
  * It's documented as above in section 2.7.4 with the programmers' model in
  * section 3.13.
  *
  * The intent of the random number is to be used as a seed for a software
  * algorithm, some older documentation suggests using the 128-bit seed to
  * generate '512 different random numbers' and the TEE_GenerateRandom()
  * function uses the board random generator when available but at the moment
  * (10:24:35 WEST Sunday, 7 August 2016) the above hardware is not being used:
  * https://github.com/OP-TEE/optee_os/issues/923.
  *
  * \param buffer The buffer to fill. This should have enough space for 32
  *               bytes.
  * \return An estimate of the total number of bits (not bytes) of entropy in
  *         the buffer on success, or a negative number if the hardware random
  *         number generator failed in any way. This may also return 0 to tell
  *         the caller that more samples are needed in order to do any
  *         meaningful statistical testing. If this returns 0, the caller
  *         should continue to call this until it returns a non-zero value.
  */
int hardwareRandom32Bytes(uint8_t *buffer)
{
    uint16_t entropy;
    uint8_t i;
    uint16_t sample;

    /*
     * At the moment (10:24:35 WEST Sunday, 7 August 2016) TEE_GenerateRandom()
     * was using the Fortuna (PRNG) algorithm . Here just assuming that each
     * sample has 4 bits of entropy.
     */
    entropy = 128;

    memset(buffer, 0, 32);

    if(!is_test)
    {
        generateRandomBytesTZ((uint8_t *)buffer, (uint32_t)32);
    }
    else
    {
        if (!broken_hwrng)
        {
            for (i = 0; i < 32; i++)
            {
                /*
                 * It does not really mater if this is not a good random
                 * generator because the most part of the values here generated
                 * are replaced or the seed is constant to create deterministic
                 * tests.
                 */
                sample = (uint8_t)rand();
                buffer[i] = (uint8_t)((uint8_t)sample ^ (uint8_t)(sample >> 8));
            }
        }
    }

    return entropy;
}

/** Set (overwrite) the persistent entropy pool.
  * \param in_pool_state A byte array specifying the desired contents of the
  *                      persistent entropy pool. This must have a length
  *                      of #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't write to non-volatile
  *         memory) occurred.
  */
bool setEntropyPool(uint8_t *in_pool_state)
{

#if POOL_CHECKSUM_LENGTH > 20
#error "POOL_CHECKSUM_LENGTH is bigger than RIPEMD-160 hash size"
#endif

    return setEntropyPoolTZ(in_pool_state);
}

/** Obtain the contents of the persistent entropy pool.
  * \param out_pool_state A byte array specifying where the contents of the
  *                       persistent entropy pool should be placed. This must
  *                       have space for #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't read from
  *         non-volatile memory, or invalid checksum) occurred.
  */
bool getEntropyPool(uint8_t *out_pool_state)
{

#if POOL_CHECKSUM_LENGTH > 20
#error "POOL_CHECKSUM_LENGTH is bigger than RIPEMD-160 hash size"
#endif

    return getEntropyPoolTZ(out_pool_state);
}

/** Initialize the persistent entropy pool to a specified state. If the
  * current entropy pool is uncorrupted, then its state will be mixed in with
  * the specified state.
  * \param initial_pool_state The initial entropy pool state. This must be a
  *                           byte array of length #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't write to
  *         non-volatile memory) occurred.
  */
bool initialiseEntropyPool(uint8_t *initial_pool_state)
{
    uint32_t hs[8];
    uint8_t current_pool_state[ENTROPY_POOL_LENGTH];
    uint8_t i;
    uint8_t j;
    uint8_t new_pool_data[2*ENTROPY_POOL_LENGTH];

    if (getEntropyPool(current_pool_state))
    {
        /* Current pool is not valid; Overwrite it. */
        return setEntropyPool(initial_pool_state);
    }
    else
    {
        sha256BeginTZ(1);

        for (i = 0, j = 0; i < ENTROPY_POOL_LENGTH; i++)
        {
            new_pool_data[j++] = current_pool_state[i];
            new_pool_data[j++] = initial_pool_state[i];
        }

        sha256WriteTZ(new_pool_data, (uint32_t)(2*ENTROPY_POOL_LENGTH), 1);

        sha256FinishTZ(hs, (uint32_t)32, 1);

        writeHashToByteArrayTZ(current_pool_state, hs, true);

        return setEntropyPool(current_pool_state);
    }
}

/** Set the persistent entropy pool to something, so that calls to
  * getRandom256() don't fail because the entropy pool is not valid. */
void initialiseDefaultEntropyPool(void)
{
  uint8_t pool_state[ENTROPY_POOL_LENGTH];

  memset(pool_state, 0, ENTROPY_POOL_LENGTH);

  initialiseEntropyPool(pool_state);
}

/** Uses a hash function to accumulate entropy from a hardware random number
  * generator (HWRNG), along with the state of a persistent pool. The
  * operations used are: intermediate = H(HWRNG | pool),
  * output = H(H(intermediate)) and new_pool = H(intermediate | padding),
  * where "|" is concatenation, H(x) is the SHA-256 hash of x and padding
  * consists of 32 0x42 bytes.
  *
  * To justify why a cryptographic hash is an appropriate means of entropy
  * accumulation, see the paper "Yarrow-160: Notes on the Design and Analysis
  * of the Yarrow Cryptographic Pseudo-random Number Generator" by J. Kelsey,
  * B. Schneier and N. Ferguson, obtained from
  * http://www.schneier.com/paper-yarrow.html on 14-April-2012. Specifically,
  * section 5.2 addresses entropy accumulation by a hash function.
  *
  * Entropy is accumulated by hashing bytes obtained from the HWRNG until the
  * total entropy (as reported by the HWRNG) is at least
  * 256 * ENTROPY_SAFETY_FACTOR bits.
  * If the HWRNG breaks in a way that is undetected, the (maybe secret) pool
  * of random bits ensures that outputs will still be unpredictable, albeit
  * not strictly meeting their advertised amount of entropy.
  * \param n The final 256 bit random value will be written here.
  * \param pool_state If use_pool_state is true, then the the state of the
  *                   persistent entropy pool will be read from and written to
  *                   this byte array. The byte array must be of
  *                   length #ENTROPY_POOL_LENGTH bytes. If use_pool_state is
  *                   false, this parameter will be ignored.
  * \param use_pool_state Specifies whether to use RAM (true) or
  *                       non-volatile memory (false) to access the persistent
  *                       entropy pool. If this is true, the persistent
  *                       entropy pool will be read/written from/to the byte
  *                       array specified by pool_state. If this is false, the
  *                       persistent entropy pool will be read/written from/to
  *                       non-volatile memory. The option of using RAM is
  *                       provided for cases where random numbers are needed
  *                       but non-volatile memory is being cleared.
  * \return false on success, true if an error (couldn't access
  *         non-volatile memory, or invalid entropy pool checksum) occurred.
  */
static bool getRandom256Internal(BigNum256 n, uint8_t *pool_state, bool use_pool_state)
{
    uint16_t total_entropy;
    uint32_t hs[8];
    int response;
    uint8_t random_bytes[MAX(32, ENTROPY_POOL_LENGTH)];
    uint8_t intermediate[32];
    uint8_t padding[] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                        0x42, 0x42, 0x42, 0x42, 0x42};

    /*
     * Hash in HWRNG randomness until we have reached the entropy reached the entropy required.
     * This needs to happen before hashing the pool itself due to possibility  of length
     * extension attacks; see below.
     */
    total_entropy = 0;

    //sha256Begin(&hs);
    sha256BeginTZ(1);

    while (total_entropy < (256 * ENTROPY_SAFETY_FACTOR))
    {
        response = hardwareRandom32Bytes(random_bytes);

        if (response < 0)
            return true;    /* HWRNG failure */

        /*
         * Sometimes hardwareRandom32Bytes() returns 0, which signifies that
         * more samples are needed in order to do statistical testing.
         * hardwareRandom32Bytes() assumes it will be repeatedly called until
         * returns a non-zero value. If anything in this while loop is changed
         * make sure the code still respects this assumption.
         */
        total_entropy = (uint16_t) (total_entropy + response);

        sha256WriteTZ(random_bytes, (uint32_t)32, 1);
    }

    /* Now include the previous state of the pool */
    if (use_pool_state)
        memcpy(random_bytes, pool_state, ENTROPY_POOL_LENGTH);
    else
    {
        if (getEntropyPool(random_bytes))
            return true;    /* Error reading from non-volatile memory, or invalid checksum */
    }


    sha256WriteTZ(random_bytes, (uint32_t)ENTROPY_POOL_LENGTH, 1);

    sha256FinishTZ(hs, (uint32_t)32, 1);

    writeHashToByteArrayTZ(intermediate, hs, true);

    /*
     * Calculate new pool state. We can't use the intermediate state as the
     * new pool, or an attacker who obtained access to the pool state could
     * determine the most recent returned random output.
     */
    sha256BeginTZ(1);

    sha256WriteTZ(intermediate, (uint32_t)32, 1);

    sha256WriteTZ(padding, (uint32_t)32, 1);

    sha256FinishTZ(hs, (uint32_t)32, 1);

    writeHashToByteArrayTZ(random_bytes, hs, true);

    /*
     * Save the pool state to non-volatile memory immediately as we don't
     * want it possible to reuse the pool state
     */
    if (use_pool_state)
        memcpy(pool_state, random_bytes, ENTROPY_POOL_LENGTH);
    else
    {
        if (setEntropyPool(random_bytes))
            return true;    /* Error writing to non-volatile memory */
    }

    /*
     * Hash the intermediate state twice to generate the random bytes to
     * return. We can't output the pool state directly, or an attacker who
     * knew that the HWRNG was broken. and how it was broken, could then
     * predict the next output. Outputting H(intermediate) is another
     * possibility, but that's kinda cutting it close though, as we're
     * outputting H(intermediate) while the next pool state will be
     * H(intermediate | padding). We've prevented a length extension attack
     * as described above, but there maybe other attacks.
     */
    sha256BeginTZ(1);

    sha256WriteTZ(intermediate, (uint32_t)ENTROPY_POOL_LENGTH, 1);

    sha256FinishDoubleTZ(hs, (uint32_t)32, 1);

    writeHashToByteArrayTZ(n, hs, true);

    return false;   /* Success */
}

/** Version of getRandom256Internal() which uses non-volatile memory to store
  * the persistent entropy pool. See getRandom256Internal() for more details.
  * \param n See getRandom256Internal()
  * \return See getRandom256Internal()
  */
bool getRandom256(BigNum256 n)
{
    return getRandom256Internal(n, NULL, false);
}

/** Version of getRandom256Internal() which uses RAM to store
  * the persistent entropy pool. See getRandom256Internal() for more details.
  * \param n See getRandom256Internal()
  * \param pool_state A byte array of length #ENTROPY_POOL_LENGTH which
  *                   contains the persistent entropy pool state. This will
  *                   be both read from and written to.
  * \return See getRandom256Internal()
  */
bool getRandom256TemporaryPool(BigNum256 n, uint8_t *pool_state)
{
    return getRandom256Internal(n, pool_state, true);
}

/** Use a combination of cryptographic primitives to deterministically
  * generate a new 256 bit number.
  *
  * The generator uses the algorithm described in
  * https://en.bitcoin.it/wiki/BIP_0032, accessed 12-November-2012 under the
  * "Specification" header. The generator generates uncompressed keys.
  *
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
bool generateDeterministic256(BigNum256 out, const uint8_t *seed, const uint32_t num)
{
    return generateDeterministic256TZ(out, seed, num);
}

/** Generate an insecure one-time password.
  * \param otp The generated one-time password will be written here. This must
  *            be a character array with enough space to store #OTP_LENGTH
  *            characters. The OTP will be null-terminated.
  * \warning The password generated by this function has dubious security
  *          properties. Do not use the password for anything private.
  */
void generateInsecureOTP(char *otp)
{
    uint8_t random_bytes[32];
    uint8_t dummy_pool_state[ENTROPY_POOL_LENGTH];
    unsigned int i;

    if (getRandom256(random_bytes))
    {
        /*
         * Sometimes an OTP maybe required when the entropy pool hasn't been
         * initialized yet (eg. when formating storage). In those cases, use
         * a RAM-based dummy entropy pool. This has poor security properties,
         * but then again, this function is called generateInsecureOTP()for
         * a reason.
         */
        memset(dummy_pool_state, 42, sizeof(dummy_pool_state));

        if (getRandom256TemporaryPool(random_bytes, dummy_pool_state))
        {
            /*
             * This function must return something, even if it is not quite
             * random.
             */
            memset(random_bytes, 42, sizeof(random_bytes));
        }
    }

#if OTP_LENGTH > 32
#error "OTP_LENGTH too big"
#endif  /* #if OTP_LENGTH > 32 */

    for (i = 0; i < (OTP_LENGTH -1); i++)
    {
        /*
         * Each character is approximately uniformly distributed between 0 and
         * 9 (inclusive). Here, "approximately" doesn't matter because this
         * function is insecure.
         */

        otp[i] = (char)('0' + (random_bytes[i] % 10));
    }

    otp[OTP_LENGTH - 1] = '\0';
}
