/** \file
  *
  * \brief Describes functions exported by test_helpers.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef TEST_PERFORMANCE_H_INCLUDED
#define TEST_PERFORMANCE_H_INCLUDED

#include "test_helpers.h"

void startTest(char * test_description);
void finishTest(void);
void TestPerformance(statistics * stats);

#endif
