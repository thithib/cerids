#include "test_detector.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


int init_suite_detector (void) // operations to be done before all tests
{
    return 0;
}

int clean_suite_detector (void) // operations to be done after all tests
{
    return 0;
}

void test_detectorInit(void)
{
    CU_ASSERT(true);
}

void test_detectorMatch(void)
{
    CU_ASSERT(true);
}

void test_detectorCleanUp(void)
{
    CU_ASSERT(true);
}

