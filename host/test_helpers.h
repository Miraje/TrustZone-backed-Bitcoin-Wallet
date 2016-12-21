/** \file
  *
  * \brief Describes functions and structures exported by test_helpers.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef TEST_HELPERS_H_INCLUDED
#define TEST_HELPERS_H_INCLUDED

#include "bignum256.h"
#include "common.h"

#include <stdio.h>

/** Structure with information about the results of tests. */
typedef struct statisticsStruct
{
	/** Number of tests passed */
	int passed;
	/** Number of tests failed */
	int failed;
	/** Total number of tests */
	int total;
	/** Execution time */
	double time;
} statistics;

void initialiseStats(statistics * stats);
void bigPrintVariableSize(const uint8_t *number, const unsigned int size, const bool is_big_endian);
void printBigEndian16(const uint8_t *buffer);
void printLittleEndian32(const BigNum256 buffer);
void fillWithRandom(uint8_t *out, unsigned int len);
void printStatistics(int tests_passed, int tests_failed, int tests_total, double time);
void printTime(double time);

#endif // #ifndef TEST_HELPERS_H_INCLUDED
