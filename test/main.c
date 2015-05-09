#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "test_config.h"
#include "test_sniffer.h"

int main(void)
{
    CU_pSuite pSuite_config = NULL;
    CU_pSuite pSuite_sniffer = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite_config = CU_add_suite("Configuration module", init_suite_config, clean_suite_config);
    pSuite_sniffer = CU_add_suite("Sniffer module", init_suite_sniffer, clean_suite_sniffer);

    if (NULL == pSuite_config || NULL == pSuite_sniffer) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite_config, "test of getConf", test_getConf)) ||
        (NULL == CU_add_test(pSuite_config, "test of getConfByArgs", test_getConfByArgs)) ||
        (NULL == CU_add_test(pSuite_config, "test of getConfByFile", test_getConfByFile)) ||
        (NULL == CU_add_test(pSuite_config, "test of getWhitelist", test_getWhitelist)) ||
        (NULL == CU_add_test(pSuite_config, "test of rulesCount", test_rulesCount)) ||
        (NULL == CU_add_test(pSuite_sniffer, "test of snifferInit", test_snifferInit)) ||
        (NULL == CU_add_test(pSuite_sniffer, "test of snifferRun", test_snifferRun)) ||
        (NULL == CU_add_test(pSuite_sniffer, "test of snifferCleanUp", test_snifferCleanUp))) {
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

