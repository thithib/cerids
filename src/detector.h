/**
 * \file config.h
 * \brief Header file for configuration module
 * \version 0.1
 */

#ifndef _DETECTOR_H
#define _DETECTOR_H

#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


int detectorInit (pcre * , char ** , pcre_extra *);
bool detectorMatch (pcre * , char * , pcre_extra * );
int detectorCleanUp (pcre * );

#endif

