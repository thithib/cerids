/**
 * \file parser.h
 * \brief Header file for parser module
 */
#ifndef _PARSER_H
#define _PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

/**
 * \def ETH_LENGTH 
 * \brief Ethernet Header Length
 */
#define ETH_LENGTH 14

/**
 * \def MAC_LENGTH 
 * \brief Mac address length 
 */
#define MAC_LENGTH 6

/**
 * \def ETH_TYPE_LENGTH 
 * \brief Length of EtherType
 */
#define ETH_TYPE_LENGTH 2

/**
 * \def IP_LENGTH 
 * \brief IPv4 Length
 */

#define IP_LENGTH 4

/**
 * \def NUMBER_METHODS 
 * \brief Number of methods
 */
#define NUMBER_METHODS 27
 

/**
 * \struct frame
 * \brief This structure holds ethernet, ip, tcp and http fields.
 */
typedef struct frame
{
    //ethernet
    u_char eth_mac_dst[6];
    u_char eth_mac_src[6];
    u_char eth_type[2]; 

    //ip
    u_char ip_vers;         
    int ip_ihl;
    u_char ip_tos;
    int ip_len; 			// Ip total length != frame total length
    u_char ip_id[2];
    u_char ip_flags_frag_offset[2];
    u_char ip_ttl;
    u_char ip_proto;
    u_char ip_checksum[2];
    u_char ip_src[4];
    u_char ip_dst[4];
    u_char* ip_options;
 
    //tcp
    int tcp_srcport;
    int tcp_dstport;
    u_char tcp_seq[4];
    u_char tcp_ack[4];
    int tcp_offset;         // size of TCP header in bytes
    u_char tcp_flags[2];
    int tcp_window_size_value;
    u_char tcp_checksum[2];
    u_char tcp_urg_pointer[2];
    u_char* tcp_options;
    u_char* tcp_data;

    //http
    u_char* http_method;
    u_char* http_request_uri;
    u_char* http_host;
} Frame;

/**
 * \struct result
 * \brief This structure holds informations about every valid HTTP request to be analyzed by the detector
 */
typedef struct result
{
    u_char ip_src[4];
    u_char ip_dst[4];
    u_char* http_method;
    u_char* http_request_uri;
    u_char* http_host;
} Result;

int parser (unsigned char* , Result* );
int frameCleanUp(Frame * frame);
int ethernetParser (Frame*, unsigned char *);
int ipParser (Frame*, unsigned char*);
int tcpParser (Frame*, unsigned char*);
int httpParser (Frame*, Result*);


#endif

