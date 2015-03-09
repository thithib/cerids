#include <tests.h>
#include "../src/config.h"

int init_suite1(void); // operations to be done before all tests

int clean_suite1(void); // operations to be done after all tests

void test_getConf(void)
{
    int argc;
    char argv = ["cerids"];
    Options *options;
    CU_ASSERT(getConf(argc, argv, options) == 0);
}

void test_getConfByArgs(void)
{
    int argc = 1;
    char argv = ["cerids"];
    Options *options;
    CU_ASSERT(getConfByArgs(argc, argv, options) == 0);
}

void getConfByFile(void)
{
    Options *options;
    CU_ASSERT(getConfByFile(options) == 0);
}

void test_getWhitelist(void)
{
    CU_ASSERT(getWhitelist() != NULL);
}

void test_rulesCount(void)
{
    CU_ASSERT(0 <= rulesCount());
}

int main(void)
{
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("Suite_1", init_suite1, clean_suite1);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "test of getConf", test_getConf)) ||
        (NULL == CU_add_test(pSuite, "test of getConfByArgs", test_getConfByArgs)) ||
        (NULL == CU_add_test(pSuite, "test of getConfByFile", test_getConfByFile)) ||
        (NULL == CU_add_test(pSuite, "test of getWhitelist", test_getWhitelist)) ||
        (NULL == CU_add_test(pSuite, "test of rulesCount", test_rulesCount)))
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}

