/**
 * \file detector.c
 * \brief Detection engine powered by libpcre
 */


#include "detector.h"
#include <syslog.h>

/**
 * \param reCompiled 
 * \param whitelist {Whitelist object from config}
 * \param reGoodies
 * \return 0 if ok, other integer if not
 */
int detectorInit (pcre * reCompiled, char ** whitelist, pcre_extra * reGoodies)
{
    int pcreErrorOffset;
    const char * pcreErrorStr;
    int len = 0, bufLen = 2;
    int i = 0;
    char * buffer = malloc(2*sizeof(char));
    buffer[0] = '(';

    // create a HUGE regexp with every wlisted page
    // Q&D method to improve speed
    while (whitelist[i] != NULL){
        len = strlen(whitelist[i]);
        bufLen += len+1;
        buffer = realloc(buffer, bufLen*sizeof(char));
        if (buffer == NULL){
            printf("ERROR: failed to allocate memory\n");
            return EXIT_FAILURE;
        }
        strncat(buffer,"|", bufLen);
        strncat(buffer, whitelist[i], bufLen);
    }

    buffer[bufLen-1] = ')';

    // regexp compilation
    reCompiled = pcre_compile(buffer, 0, &pcreErrorStr, &pcreErrorOffset, NULL);
    if (reCompiled == NULL) {
        printf("ERROR: Could not compile '%s': %s\n", buffer, pcreErrorStr);
        return EXIT_FAILURE;
    }

    // optimize goodies
    reGoodies = pcre_study(reCompiled, 0, &pcreErrorStr);

    if (pcreErrorStr != NULL) {
        printf("ERROR: Could not study '%s': %s\n", buffer, pcreErrorStr);
        return EXIT_FAILURE;
    }

    // free buffer
    free(buffer);

    return EXIT_SUCCESS;
}

/**
 *  * \param reCompiled { pointer to precompiled regex string }
 *   * \param pcreExtra { pointer to result of regex optimization }
 *    * \param rule { pointer to a string to match }
 *     * \return true if matches found, false if not
 *      */
bool detectorMatch (pcre* reCompiled, pcre_extra* pcreExtra, char* rule)
{
    int pcreExecRet;

    pcreExecRet = pcre_exec(reCompiled,
            pcreExtra,
            rule,
            strlen(rule),   // length of string
            0,              // start looking at this point
            0,              // Options
            NULL,           // subStrVec, in case of substrings        handling
            0);             // length of subStrVec

    return (pcreExecRet >= 0);
}

/**
 *  * \param reCompiled { pointer to precompiled regex string }
 *   * \param pcreExtra { pointer to result of regex optimization }
 *    * \return 0 if ok
 *     */
int detectorCleanUp (pcre* reCompiled, pcre_extra* pcreExtra)
{
    pcre_free(reCompiled);

    if (pcreExtra != NULL)
        pcre_free(pcreExtra);

    return 0;
}

