#include "config.h"
#include <unistd.h>

extern int optind;

int init_suite1(void);
int clean_suite1(void);

void test_getConf(void);
void test_getConfByArgs(void);
void test_getConfByFile(void);
void test_getWhitelist(void);
void test_rulesCount(void);
