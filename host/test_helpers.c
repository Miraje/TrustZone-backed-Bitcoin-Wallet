/** \file
  *
  * \brief Common helper functions for unit tests.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "test_helpers.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void initialiseStats(statistics * stats)
{
	stats->passed = 0;
	stats->failed = 0;
	stats->total = 0;
	stats->time = 0;
}

/** Display a multi-precision integer of arbitrary size as a hex string.
  * \param number The byte array containing the integer.
  * \param size The size, in number of bytes, of the byte array.
  * \param is_big_endian This should be true if the integer is stored in
  *                      big-endian format and should be false if the number
  *                      is stored in little-endian format.
  */
void bigPrintVariableSize(const uint8_t *number, const unsigned int size, const bool is_big_endian)
{
	unsigned int i;
	if (is_big_endian)
	{
		for (i = 0; i < size; i++)
			printf("%02x", number[i]);
	}
	else
	{
		for (i = (uint8_t)(size - 1); i < size; i--)
			printf("%02x", number[i]);
	}
}

/** Display a 128 bit big-endian multi-precision integer as a hex string.
  * \param buffer 16 byte array containing the number to display.
  */
void printBigEndian16(const uint8_t *buffer)
{
	bigPrintVariableSize(buffer, 16, true);
}

/** Display a 256 bit little-endian multi-precision integer as a hex string.
  * \param buffer 32 byte array containing the number to display.
  */
void printLittleEndian32(const BigNum256 buffer)
{
	bigPrintVariableSize(buffer, 32, false);
}

/** Fill array with pseudo-random testing data.
  * \param out Byte array to fill.
  * \param len Number of bytes to write.
  */
void fillWithRandom(uint8_t *out, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
	{
		out[i] = (uint8_t)rand();
	}
}

void printStatistics(int tests_passed, int tests_failed, int tests_total, double time)
{
	printf("+---------------------------------------%29s\n","----------------------------+");
	printf("|                           STATISTICS  %29s\n","|");
	printf("+---------------------------------------%29s\n","----------------------------+");
	printf("|   TIME                |  %7g seconds  %25s\n",time, "|");
    printf("+---------------------------------------%29s\n","----------------------------+");
    printf("|   CLOCKS_PER_SEC      |  %7ld         %26s\n", CLOCKS_PER_SEC, "|");
	printf("+---------------------------------------%29s\n","----------------------------+");
	printf("|   SUCCEEDED     TESTS |  %7d tests    %25s\n", tests_passed, "|");
	printf("+---------------------------------------%29s\n","----------------------------+");
	printf("|   FAILED        TESTS |  %7d tests    %25s\n", tests_failed, "|");
	printf("+---------------------------------------%29s\n","----------------------------+");
	printf("|   TOTAL         TESTS |  %7d tests    %25s\n", tests_total, "|");
	printf("+---------------------------------------%29s\n","----------------------------+");
}

void printTime(double time)
{
	printf("\n+---------------------------------------%25s\n","----------------------------+");
	printf("|                         EXECUTION TIME  %27s\n","|");
	printf("+-----------------------------------------%27s\n","--------------------------+");
	printf("|   TIME                |  %8g seconds    %22s\n",time, "|");
    printf("+-----------------------------------------%27s\n","--------------------------+");
    printf("|   CLOCKS_PER_SEC      |  %8ld           %23s\n",CLOCKS_PER_SEC, "|");
	printf("+-----------------------------------------%27s\n","--------------------------+");
}
