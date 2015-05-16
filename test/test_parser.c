#include "test_parser.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


int init_suite_parser (void) // operations to be done before all tests
{
    return 0;
}

int clean_suite_parser (void) // operations to be done after all tests
{
    return 0;
}

void test_parser (void)
{
    CU_ASSERT(1 > 0);
}

void test_ethernetParser (void)
{
    CU_ASSERT(1 > 0);
}

void test_ipParser (void)
{
    CU_ASSERT(1 > 0);
}

void test_tcpParser (void)
{
    CU_ASSERT(1 > 0);
}

void test_httpParser (void)
{
    CU_ASSERT(1 > 0);
}

