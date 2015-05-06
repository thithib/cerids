#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "test_config.h"

int main(void)
{
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("Module de configuration", init_suite1, clean_suite1);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "test of getConf", test_getConf)) ||
        (NULL == CU_add_test(pSuite, "test of getConfByArgs", test_getConfByArgs)) ||
        (NULL == CU_add_test(pSuite, "test of getConfByFile", test_getConfByFile)) ||
        (NULL == CU_add_test(pSuite, "test of getWhitelist", test_getWhitelist)) ||
        (NULL == CU_add_test(pSuite, "test of rulesCount", test_rulesCount))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    printf("\n");
    CU_basic_show_failures(CU_get_failure_list());
    printf("\n\n");

    CU_cleanup_registry();
    return CU_get_error();
}

