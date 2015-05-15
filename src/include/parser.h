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
 	int ip_len; 			// Ip total length != frame total length
 	u_char ip_id[2];
 	u_char ip_flags_frag_offset[2];
 	u_char ip_ttl;
 	u_char ip_proto;
 	u_char ip_checksum[2];
 	u_char ip_src[4];
 	u_char ip_dst[4];
 	
 		//OPTIONS
 			//TO DO
 //tcp
 	int tcp_srcport;
 	int tcp_dstport;
 	u_char tcp_seq[4];
 	u_char tcp_ack[4];
 	int tcp_offset;
 	u_char tcp_flags[2];
 	int tcp_window_size_value;
 	u_char tcp_checksum[2];
 	u_char tcp_urg_pointer[2];
 	u_char* tcp_options;
 	u_char* tcp_data;

 //http
 	u_char* http_method;
 	u_char* http_request_uri;
 };



#endif

