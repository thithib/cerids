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
int parser(int frame_length, unsigned char* f);

 struct frame
 {
 //ethernet
 	u_char mac_dst[6];
 	u_char mac_src[6];
 	u_char eth_type[2]; 

 //ip
 	u_char ip_vers_ihl;         // 4 first bits are for ip version, 4 next ip are for nternet header length, header length = ihl*32bits
 	u_char ip_tos;
 	u_char ip_len[2]; 			// Ip total length != frame total length
 	u_char ip_id[2];
 	u_char ip_flags_frag_offset[2];
 	u_char ip_ttl;
 	u_char ip_proto;
 	u_char ip_checksum[2];
 	u_char ip_src[4];
 	u_char ip_dst[4];
 	
 		//OPTIONS
 //tcp
 	u_char tcp_srcport[4];
 	u_char tcp_dstport[4];
 	
 };



#endif

