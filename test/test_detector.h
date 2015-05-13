#ifndef _TEST_DETECTOR_H
#define _TEST_DETECTOR_H

#include "detector.h"

int init_suite_detector(void);
int clean_suite_detector(void);

void test_detectorInit(void);
void test_detectorMatch(void);
void test_detectorCleanUp(void);

#endif

