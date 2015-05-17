#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "test_config.h"
#include "test_sniffer.h"
#include "test_detector.h"
#include "test_parser.h"

int main(void)
{
    CU_pSuite pSuite_config = NULL;
    CU_pSuite pSuite_sniffer = NULL;
    CU_pSuite pSuite_detector = NULL;
    CU_pSuite pSuite_parser = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite_config = CU_add_suite("Configuration module", init_suite_config, clean_suite_config);
    pSuite_sniffer = CU_add_suite("Sniffer module", init_suite_sniffer, clean_suite_sniffer);
    pSuite_detector = CU_add_suite("Detector module", init_suite_detector, clean_suite_detector);
    pSuite_parser = CU_add_suite("Parser module", init_suite_parser, clean_suite_parser);

    if (NULL == pSuite_config || NULL == pSuite_sniffer || NULL == pSuite_detector || NULL == pSuite_parser) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite_config, "test of getConfByArgs", test_getConfByArgs)) ||
        (NULL == CU_add_test(pSuite_config, "test of getConfByFile", test_getConfByFile)) ||
        (NULL == CU_add_test(pSuite_config, "test of getWhitelist", test_getWhitelist)) ||
        (NULL == CU_add_test(pSuite_config, "test of getConf", test_getConf)) ||
        (NULL == CU_add_test(pSuite_config, "test of rulesCount", test_rulesCount)) ||
        (NULL == CU_add_test(pSuite_sniffer, "test of snifferInit", test_snifferInit)) ||
        (NULL == CU_add_test(pSuite_sniffer, "test of snifferRun", test_snifferRun)) ||
        (NULL == CU_add_test(pSuite_sniffer, "test of snifferCleanUp", test_snifferCleanUp)) ||
        (NULL == CU_add_test(pSuite_detector, "test of detectorInit", test_detectorInit)) ||
        (NULL == CU_add_test(pSuite_detector, "test of detectorMatch", test_detectorMatch)) ||
        (NULL == CU_add_test(pSuite_detector, "test of detectorCleanUp", test_detectorCleanUp)) ||
        (NULL == CU_add_test(pSuite_parser, "test of ethernetParser", test_ethernetParser)) ||
        (NULL == CU_add_test(pSuite_parser, "test of ipParser", test_ipParser)) ||
        (NULL == CU_add_test(pSuite_parser, "test of tcpParser", test_tcpParser)) ||
        (NULL == CU_add_test(pSuite_parser, "test of httpParser", test_httpParser)) ||
        (NULL == CU_add_test(pSuite_parser, "test of parser", test_parser))) {
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

