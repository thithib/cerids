/**
 * \file config.h
 * \brief Header file for configuration module
 * \version 0.1
 */

#ifndef _CONFIG_H
#define _CONFIG_H


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

/**
 * \def CONF_FILE
 * \brief Configuration file path
 */
#define CONF_FILE "../conf/cerids.conf"

/**
 * \def WHITELIST_FILE
 * \brief Whitelist file path
 */
#define WHITELIST_FILE "../conf/whitelist.txt"

/**
 * \def BUFFER_LENGTH
 * \brief Buffer max length
 */
#define BUFFER_LENGTH 1000

/**
 * \def OPT_NAME_LENGTH
 * \brief optName max length
 */
#define OPT_NAME_LENGTH 20

/**
 * \def OPT_VALUE_LENGTH
 * \brief optValue max length
 */
#define OPT_VALUE_LENGTH 100

/**
 * \struct Options
 * \brief Configuration options
 * 
 * This structure holds the CerIDS configuration options
 */
typedef struct Options {
    char *dev;
    char *filename;
    int port;
    bool live;
    bool debug;
    bool foreground;
} Options;

void usage(char *binname);
void help(char *binname);
int getConf(int argc, char *argv[], Options *options);
int getConfByArgs(int argc, char *argv[], Options *options);
int getConfByFile(Options *options);
char** getWhitelist(void);
int rulesCount(void);

#endif
