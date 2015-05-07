/**
 * \file sniffer.h
 * \brief Header file for sniffer module
 * \version 0.1
 */

#ifndef _SNIFFER_H
#define _SNIFFER_H

#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include "config.h"


int snifferInit (Options *options, pcap_t ** handle);
int snifferRun (pcap_t ** handle, pcap_handler callback);
void snifferCleanUp(pcap_t ** handle);

#endif
