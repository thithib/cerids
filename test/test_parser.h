#ifndef _TEST_PARSER_H
#define _TEST_PARSER_H

#include "parser.h"

int init_suite_parser(void);
int clean_suite_parser(void);

void test_parser (void);
void test_ethernetParser (void);
void test_ipParser (void);
void test_tcpParser (void);
void test_httpParser (void);

int generateFrames (u_char *, u_char *, u_char *);

#endif

