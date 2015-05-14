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
    pcre* reCompiled = NULL;
    char* whitelist[] = {"test", "passed", NULL};
    pcre_extra* pcreExtra = NULL;

    CU_ASSERT(detectorInit(reCompiled, whitelist, pcreExtra) == EXIT_SUCCESS);

    pcre_free(reCompiled);
    if (pcreExtra != NULL)
        pcre_free(pcreExtra);
}

void test_detectorMatch(void)
{
    char string1[] = "fastest", string2[] = "slowest";
    char* whitelist[] = {"f[a-c](.+)", NULL};
    pcre* reCompiled = NULL;
    pcre_extra* pcreExtra = NULL;

    detectorInit(reCompiled, whitelist, pcreExtra);

    CU_ASSERT_TRUE(detectorMatch(reCompiled, pcreExtra, string1));
    CU_ASSERT_FALSE(detectorMatch(reCompiled, pcreExtra, string2));
    
    pcre_free(reCompiled);
    if (pcreExtra != NULL)
        pcre_free(pcreExtra);
}

void test_detectorCleanUp(void)
{
    pcre* reCompiled = NULL;
    char* whitelist[] = {"test", "passed", NULL};
    pcre_extra* pcreExtra = NULL;

    detectorInit(reCompiled, whitelist, pcreExtra);

    CU_ASSERT(detectorCleanUp(reCompiled, pcreExtra) == 0);
}

