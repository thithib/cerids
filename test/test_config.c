#include "test_config.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


int init_suite_config(void) // operations to be done before all tests
{
    return 0;
}

int clean_suite_config(void) // operations to be done after all tests
{
    return 0;
}

void test_getConf(void)
{
    int argc;
    char *argv1[3] = {"cerids", "-i", "eth0"};
    char *argv2[2] = {"cerids", "-d"};
    char *argv3[5] = {"cerids", "-i", "eth0", "-p", "0"};

    Options *options = malloc(sizeof(Options));
    argc = 3;
    CU_ASSERT(getConf(argc, argv1, options) == 0);
    free(options);
   
    options = malloc(sizeof(Options));
    argc = 2;
    optind = 0;
    CU_ASSERT(getConf(argc, argv2, options) == 2);
    free(options);

    options = malloc(sizeof(Options));
    argc = 5;
    optind = 0;
    CU_ASSERT(getConf(argc, argv3, options) == 3);
    free(options);
}

void test_getConfByArgs(void)
{
    int argc = 8;
    char *argv[8] = {"cerids", "-d", "-i", "eth0", "-f" , "test", "-p", "80"};
    Options *options = malloc(sizeof(Options));
    optind = 0;

    CU_ASSERT(getConfByArgs(argc, argv, options) == 0);
    CU_ASSERT(options->debug && options->foreground && strcmp(options->dev, "eth0") == 0 
            && options->filename != NULL && options->port == 80);

    free(options);
}

void test_getConfByFile(void)
{
    Options *options = malloc(sizeof(Options));

    CU_ASSERT(getConfByFile(options) == 0);
    CU_ASSERT(!options->debug);

    free(options);
}

void test_getWhitelist(void)
{
    CU_ASSERT(getWhitelist() != NULL);
}

void test_rulesCount(void)
{
    CU_ASSERT(0 <= rulesCount());
}

