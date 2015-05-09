#include "config.h"
#include <unistd.h>

extern int optind;

int init_suite_config(void);
int clean_suite_config(void);

void test_getConf(void);
void test_getConfByArgs(void);
void test_getConfByFile(void);
void test_getWhitelist(void);
void test_rulesCount(void);
