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
    int opt;

    // set defaults
    options->port = 80;
    options->dev = NULL;
    options->filename = NULL;
    options->debug = false;
    options->foreground = false;

    getConfByFile(options);
    getConfByArgs(argc, argv, options);

    if ( (options->filename == NULL && options->dev == NULL)
          || (options->filename != NULL && options->dev != NULL) ) {
        syslog(LOG_ERR, "Only one of filename and interface can be used at the same time\n");
        return 2;
    }

    if ( options->port < 1 || options->port > 65535) {
        syslog(LOG_ERR, "Invalid port number\n");
        return 3;
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

        while ((opt = getopt(argc, argv, "df:i:p:")) != -1){
            switch (opt) {
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
                options->port = atoi(optarg);
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

    if ((ceridsConf = fopen(CONF_FILE, "r")) == NULL) {
        syslog(LOG_ERR, "Can't open conf file\n");
        return -1;
    }

    while (fgets(buffer, BUFFER_LENGTH, ceridsConf) != NULL) {

        position = strchr(buffer, '#'); // commentaires
        *position = '\0';

        if (strlen(buffer) != 0) { // la  ligne n'est pas "uniquement" un commentaire

            strncpy(optName, strtok(buffer, delim), OPT_NAME_LENGTH);
            strncpy(optValue, strtok(buffer, delim), OPT_VALUE_LENGTH);

            if (optName == "dev")
                options->dev = optValue;
            else if (optName == "filename")
                options->filename = optValue;
            else if (optName == "port")
                options->port = atoi(optValue);
            else if (optName == "live")
                options->live = (optValue == "true") ? true : false;
            else if (optName == "debug")
                options->debug = (optValue == "true") ? true : false;
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

    if ((whitelist = fopen(WHITELIST_FILE, "r")) == NULL) {
        syslog(LOG_ERR, "Can't open whitelist file\n");
        return NULL;
    }

    if ((rules = malloc((1+rulesCount())*sizeof(char*))) == NULL) {
        syslog(LOG_ERR, "Memory allocation error\n");
        return NULL;
    }

    while (fgets(buffer, BUFFER_LENGTH, whitelist) != NULL) {

        if ((*(rules+i) = malloc(strlen(buffer)*sizeof(char))) == NULL) {
            syslog(LOG_ERR, "Memory allocation error\n");
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
    FILE *f = fopen(WHITELIST_FILE, "r");
    int c, lines = 0;

    if (f == NULL)
        return 0;

    while ((c = fgetc(f)) != EOF)
        if (c == '\n')
            ++lines;

    fclose(f);

    return lines;
}

void usage(char *binname)
{
    fprintf(stderr, "Usage: %s [-d][-f filename] [-i device] [-p port]\n", binname);
    exit(EXIT_FAILURE);
}

