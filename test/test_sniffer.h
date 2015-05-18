#ifndef _TEST_SNIFFER_H
#define _TEST_SNIFFER_H

#include <time.h>
#include "sniffer.h"
#include "detector.h"
#include "parser.h"

int init_suite_sniffer(void);
int clean_suite_sniffer(void);

void test_snifferInit(void);
void test_snifferRun(void);
void test_snifferCleanUp(void);

void pktcallback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet);
void logMatch(FILE * fh, Result * pResult);
void getDate(char * date);

#endif

