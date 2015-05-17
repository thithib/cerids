/**
 * \file config.c
 * \brief Load configuration and whitelist
 */

#include "config.h"
#include <syslog.h>

/**
 * \param argc
 * \param argv
 * \param options { Pointer to an options structure }
 * \return 0 if ok, other integer if not
 */
int getConf(int argc, char *argv[], Options *options)
{
    // set defaults
    options->filter = strdup("port 80");
    options->dev = NULL;
    options->filename = NULL;
    options->debug = false;
    options->foreground = false;
    options->verbose = 0;

    if (!(getConfByFile(options) == 0 && getConfByArgs(argc, argv, options) == 0))
        return 1;

    if ( (options->filename == NULL && options->dev == NULL)
            || (options->filename != NULL && options->dev != NULL) ) {
        syslog(LOG_ERR, "Only one of filename and interface can be used at the same time\n");
        return 2;
    }

    return 0;
}

/**
 * \param argc
 * \param argv
 * \options { Pointer to an options structure }
 * \return 0 if ok, other integer if not
 */
int getConfByArgs(int argc, char *argv[], Options *options)
{
    int opt;

    while ((opt = getopt(argc, argv, "hdvf:i:p:")) != -1){
        switch (opt) {
            case 'h':
                help(argv[0]);
                break;
            case 'd':
                options->debug = true;
                options->foreground = true;
                break;
            case 'f':
                options->filename = strdup(optarg);
                options->foreground = true;
                break;
            case 'i':
                options->dev = strdup(optarg);
                break;
            case 'p':
                options->filter = strdup(optarg);
                break;
            case 'v':
                options->verbose++;
                break;
            default:
                usage(argv[0]);
        }

    } 

    return 0;
}

/**
 * \param options { Pointer to an options structure }
 * \return 0 if ok, other integer if not
 */
int getConfByFile(Options *options)
{
    FILE *ceridsConf = NULL;
    char optName[OPT_NAME_LENGTH], optValue[OPT_VALUE_LENGTH];
    char buffer[BUFFER_LENGTH];
    char *position, delim[] = "=";

    if ((ceridsConf = fopen(MAIN_CONF_FILE, "r")) == NULL)
        syslog(LOG_DEBUG, "Cannot open main conf file");

    if ((ceridsConf = fopen(LOCAL_CONF_FILE, "r")) == NULL)
        syslog(LOG_DEBUG, "Cannot open local conf file");

    if (ceridsConf == NULL)
        return 0;

    while (fgets(buffer, BUFFER_LENGTH, ceridsConf) != NULL) {

        position = strchr(buffer, '#'); // commentaires
        if (position != NULL)
            *position = '\0';

        if (strlen(buffer) > 1) { // current line is not empty nor only a commentary

            strncpy(optName, strtok(buffer, delim), OPT_NAME_LENGTH);
            strncpy(optValue, strtok(NULL, delim), OPT_VALUE_LENGTH);

            if (strcmp(optName, "dev") == 0)
                options->dev = (strcmp(optValue, "NULL") == 0) ? NULL : optValue;
            else if (strcmp(optName, "filename") == 0)
                options->filename = (strcmp(optValue, "NULL") == 0) ? NULL : optValue;
            else if (strcmp(optName, "filter") == 0)
                options->filter = (strcmp(optValue, "NULL") == 0) ? NULL : strdup(optValue);
            else if (strcmp(optName, "live") == 0)
                options->live = (strcmp(optValue, "true") == 0) ? true : false;
            else if (strcmp(optName, "debug") == 0)
                options->debug = (strcmp(optValue, "true") == 0) ? true : false;
            else {
                syslog(LOG_ERR, "Error in conf file: bad option name\n");
                return -1;
            }

        }

    }

    fclose(ceridsConf);

    return 0;
}

/**
 * \return An array of strings containing all regex from the whitelist, or NULL if some errors
 */
char** getWhitelist(void)
{
    FILE *whitelist = NULL;
    char buffer[BUFFER_LENGTH];
    char **rules = NULL;
    int i = 0;

    if ((whitelist = fopen(MAIN_WHITELIST_FILE, "r")) == NULL)
        syslog(LOG_DEBUG, "Cannot open main whitelist file");

    if ((whitelist = fopen(LOCAL_WHITELIST_FILE, "r")) == NULL)
        syslog(LOG_DEBUG, "Cannot open local whitelist file");

    if (whitelist == NULL) {
        syslog(LOG_ERR, "No whitelist found");
        return NULL;
    }

    if ((rules = malloc((1+rulesCount())*sizeof(char*))) == NULL) {
        syslog(LOG_ERR, "Memory allocation error");
        return NULL;
    }

    while (fgets(buffer, BUFFER_LENGTH, whitelist) != NULL) {

        if ((*(rules+i) = malloc(strlen(buffer)*sizeof(char))) == NULL) {
            syslog(LOG_ERR, "Memory allocation error");
            return NULL;
        }

        strcpy(*(rules+i), buffer);

        ++i;

    }

    *(rules+i) = NULL;

    fclose(whitelist);

    return rules;
}

/**
 * \return Number of lines in the whitelist
 */
int rulesCount(void)
{
    FILE *whitelist = NULL;
    int c, lines = 0;
    
    if ((whitelist = fopen(MAIN_WHITELIST_FILE, "r")) == NULL)
        syslog(LOG_DEBUG, "Cannot open main whitelist file");

    if ((whitelist = fopen(LOCAL_WHITELIST_FILE, "r")) == NULL)
        syslog(LOG_DEBUG, "Cannot open local whitelist file");

    if (whitelist == NULL)
        return 0;

    while ((c = fgetc(whitelist)) != EOF)
        if (c == '\n')
            ++lines;

    fclose(whitelist);

    return lines;
}

void usage(char *binname)
{
    fprintf(stderr, "Usage: %s [-h] [-d] [-vvv] [-f filename] [-i device] [-p <pcap filter>] \n", binname);
    exit(EXIT_FAILURE);
}

void help(char *binname)
{
    printf("Usage: %s [-h] [-d] [-vvv] [-f filename] [-i device] [-p <pcap filter>]\n", binname);
    puts("-d\t\t\tActivate debug mode");
    puts("-v\t\t\tVerbosity (add more -v to be more verbose");
    puts("-f <filename>\t\tRead data from a pcap file (Cannot be used with -i)");
    puts("-i <device>\t\tRead packet from an interface (Cannot be used with -f)");
    puts("-p <port>\t\tModify the pcap filter (pcap style, default: \"port 80\")");
    exit(EXIT_SUCCESS);
}
