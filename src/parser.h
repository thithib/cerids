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

//Structure of ip frame

 struct frame
 {
 //ethernet
 	u_char mac_dst[12];
 	u_char mac_src[12];
 	u_char eth_type[4]; 

 //ip
 	u_char ip_vers;
 	//ipv4	
 	u_char ihl4;				//Internet header length(for ipv4), header length =ihl*32bits
 	u_char ip_tos[2];
 	u_char ip_len[4]; 			// Ip total length != frame total length
 	u_char ip_id[4];
 	u_char ip_flags_frag_offset[4];
 	u_char ip_ttl[2];
 	u_char ip_proto[2];
 	u_char ip_checksum[4];
 	u_char ip_src[8];
 	u_char ip_dst[8];
 	
 		//OPTIONS

 	//ipv6
 	u_char ipv6_class_flow[8]; 	//Traffic Class & Flow Label
 	u_char ipv6_plen[4];	 	//Payload Length
 	u_char ipv6_nxt[2];			//Next Header 
 	u_char ipv6_hlim[2];		//Hop limit
 	u_char ipv6_src[32];				
 	u_char ipv6_dst[32];
 		//OPTIONS
 //tcp
 	u_char tcp_srcport[4];
 	u_char tcp_dstport[4];
 	
 };



#endif

