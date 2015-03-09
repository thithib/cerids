/*
 * =====================================================================================
 *
 *       Filename:  config.c
 *
 *    Description:  load config and whitelist
 *
 *        Version:  1.0
 *        Created:  06/03/2015 23:26:54
 *       Revision:  none
 *       Compiler:  gcc
 *
 * =====================================================================================
 */

#include <config.h>

Options getConf(int argc, char *argv[])
{
    int opt;
    Options options;

    // set defaults
    options.port = 80;
    options.dev = NULL;
    options.filename = NULL;

    options = getConfByFile();
    options = getConfByArgs();

    if ( (options.filename == NULL && options.dev == NULL)
          || (options.filename != NULL && options.dev != NULL) )
        fprintf(stderr, "Only one of filename and interface can be used at the same time\n");

    if ( options.port < 1 || options.port > 65535)
        fprintf(stderr, "Invalid port number\n");
 
    return options;
}

Options getConfByArgs(int argc, char *argv[])
{
      while ((opt = getopt(argc, argv, "f:i:p:")) != -1){
        switch (opt) {
        case 'f':
         options.filename = strdup(optarg);
         break;
        case 'i':
         options.dev = strdup(optarg);
         break;
         case 'p':
         options.port = atoi(optarg);
         break;
         default:
         usage(argv[0]);
        }

    } 

    return options;
}

Options getConfByFile()
{
    FILE *ceridsConf = NULL;
    Options options;
    char optName[OPT_NAME_LENGTH], optValue[OPT_VALUE_LENGTH];
    char buffer[BUFFER_LENGTH];
    char position;

    if ((ceridsConf = fopen(CONF_FILE, "r")) == NULL)
        fprintf(stderr, "Can't open conf file\n");

    while (fgets(buffer, BUFFER_LENGTH, ceridsConf) != NULL) {

        position = strchr(buffer, '#'); // commentaires
        *(buffer+position) = '\0';

        if (strlen(buffer) != 0) { // la  ligne n'est pas "uniquement" un commentaire

            strncpy(optName, strtok(buffer, '='), OPT_NAME_LENGTH);
            strncpy(optValue, strtok(buffer, '='), OPT_VALUE_LENGTH);

            switch (optName) {
                case "dev":
                    options.dev = optValue;
                    break;
                case "filename":
                    options.filename = optValue;
                    break;
                case "port":
                    options.port = atoi(optValue);
                    break;
                case "live":
                    options.live = (optValue == "true") ? true : false;
                    break;
                default:
                    fprintf(stderr, "Error in conf file: bad option name\n");
            }

        }

    }

    fclose(ceridsConf);

    return options;
}

char** getWhiteList()
{
    FILE *whitelist = NULL;
    char buffer[BUFFER_LENGTH];
    char **rules = NULL;
    int i = 0;

    if ((whitelist = fopen(WHITELIST_FILE, "r")) == NULL)
        fprintf(stderr, "Can't open whitelist file\n");

    if ((rules = malloc((1+rulesCount())*sizeof(char*))) == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return NULL;
    };

    while (fgets(buffer, BUFFER_LENGTH, whitelist) != NULL) {

        if ((*(rules+i) = malloc(strlen(buffer)*sizeof(char))) == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            return NULL;
        }
        
        strcpy(*(rules+i), buffer);

        ++i;

    }

    *(rules+i) = NULL;
    
    fclose(whitelist);

}

int rulesCount()
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
