/** \file
  *
  * \brief Entry point for hardware Bitcoin wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "extern.h"
#include "hwinterface.h"
#include "test_helpers.h"
#include "test_performance.h"
#include "test_prandom.h"
#include "test_stream.h"
#include "test_transaction.h"
#include "test_wallet.h"
#include "tz_functions.h"

#include <stdio.h>
#include <stdlib.h>

/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(int argc, char const *argv[])
{
	#ifdef TESTING
		statistics tests_stats;

		initialiseExternVariables();
		initialiseStats(&tests_stats);

		// initialiseTZ();
		// TestPerformance(&tests_stats);
		// terminateTZ();

		initialiseTZ();
		TestPerformanceStreams(&tests_stats);
		terminateTZ();

		// initialiseTZ();
		// TestPrandom(&tests_stats);
		// terminateTZ();

		// initialiseTZ();
		// TestWallet(&tests_stats);
		// terminateTZ();

		// initialiseTZ();
		// TestTransaction(&tests_stats);
		// terminateTZ();

		/* TODO REMOVE THIS TEST? IT IS THE SAME THING ALMOST */
		//TestStreams(&tests_stats);

		printf("\n=====================================================================================================================================================\n");

		printf("Global statistics\n\n");

		printStatistics(tests_stats.passed, tests_stats.failed, tests_stats.total, tests_stats.time);

		printf("=====================================================================================================================================================\n\n");

		printf("\n");

	#else

		initialiseExternVariables();
		initialiseTZ();

		while (true)
			processPacket();

		terminateTZ();

	#endif

	return 0;
}
