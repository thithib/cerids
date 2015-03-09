#ifndef _CONFIG_H
#define _CONFIG_H

/*
 * =====================================================================================
 *
 *       Filename:  config.h
 *
 *    Description:  header file of the config module
 *
 *        Version:  1.0
 *        Created:  06/03/2015 23:26:04
 *       Revision:  none
 *       Compiler:  gcc
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#define CONF_FILE "../conf/cerids.conf"
#define WHITELIST_FILE "../conf/whitelist.txt"

#define BUFFER_LENGTH 1000
#define OPT_NAME_LENGTH 20
#define OPT_VALUE_LENGTH 100

typedef struct Options {
    char *dev;
    char *filename;
    int port;
    bool live;
};

Options getConf(int argc, char *argv[]);
Options getConfByArgs(int argc, char *argc[]);
Options getConfByFile();
char** getWhitelist();
int rulesCount();

#endif
