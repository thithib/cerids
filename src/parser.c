/**
 * \file parser.c
 * \brief HTTP Parser
 */

#include "parser.h"

//Doesn't work with frames with options

int parser(int frame_length, unsigned char *f){
	struct frame frame;
	int i;
//Ethernet
	//mac addresses
	for(i = 0; i < 6; i++){
		frame.mac_dst[i] = f[i];
		frame.mac_src[i] = f[6+i];
	}
	//1st test : is the frame a ip frame ?
	bool type4Bool = true;
	u_char eth_type4[] = {0x08, 0x00}; // if ipv4 frame, type is 0800
	for(i = 0; i < 2; i++){
		frame.eth_type[i] = f[12+i];
		if (frame.eth_type[i] != eth_type4[i])
			type4Bool = false;
	}
	if(!type4Bool){
		printf("\nIt is not an ip frame\n");
		return EXIT_FAILURE;
	}
//IP
	//2nd test : is the version of ip 4  ?
	frame.ip_vers_ihl = f[14];
	if(frame.ip_vers_ihl != 0x45 )
	{
		printf("ip version isn't 4\n");
		return EXIT_FAILURE;
	}

	//type of service
	frame.ip_tos=f[15];
	//length of ip packet 
	for(i = 0; i < 2; i++)
		frame.ip_len[i] = f[16+i];

	//id
	for(i = 0; i < 2; i++)
		frame.ip_id[i] = f[18+i];

	//flags : 3bits et fragments offset : 13 bits
	for(i = 0; i < 2; i++)
		frame.ip_flags_frag_offset[i] = f[20+i];
	//ttl
	frame.ip_ttl = f[22];

	//protocol, 3rd test : if protocol is tcp, ip_proto is 06
	frame.ip_proto = f[23];
	if(frame.ip_proto != 0x06){
	printf("\nThe protocol isn't tcp\n");
	return EXIT_FAILURE;
	}

	//checksum
	for(i = 0; i < 2; i++)
		frame.ip_checksum[i] = f[24+i];
	
	// Source and destination ip
	for(i = 0; i < 4; i++){
		frame.ip_src[i] = f[26+i];
		frame.ip_dst[i] = f[30+i]; 
	}
	
	//Options
	//There is an option field if ihl != 5 (!= 20 bytes)
	//
	// TO DO
	//

// TCP
	//ports
		frame.tcp_srcport = 16*16*(int)(u_char)f[34] + (int)(u_char)f[35];
		frame.tcp_dstport = 16*16*(int)(u_char)f[36] + (int)(u_char)f[37];
	
	//sequence number and acknowledgement numbers
	for(i = 0; i < 4; i++){
		frame.tcp_seq[i] = f[38+i];
		frame.tcp_ack[i] = f[42+i];
	}
	
	//flags and offset
	for(i = 0; i < 2; i++)
		frame.tcp_flags[i] = f[46+i];

	//offset is the 4 first bits of flags
	frame.tcp_offset = 4*(int)( (frame.tcp_flags[0] & 240) >> 4 );

	frame.tcp_flags[0] &= 15;

	//windows size value
	frame.tcp_window_size_value= 16*16*(int)(u_char)f[48] + (int)(u_char)f[49];

	//checksum
	for(i = 0; i < 2; i++)
		frame.tcp_checksum[i] = f[50+i]; 
	//urg pointer
	for(i = 0; i < 2; i++)
		frame.tcp_urg_pointer[i] = f[52+i];
	//TCP options
	frame.tcp_options = malloc( (frame.tcp_offset - 20) * sizeof(u_char) );
	for(i = 0; i < frame.tcp_offset - 20 ; i++)
		frame.tcp_options[i] = f[54+i];


//Test 
	printf("\nThe destination mac address is : ");
	for(i = 0; i < 5 ;i++)
		printf("%02x:", frame.mac_dst[i]);
	printf("%02x\n",frame.mac_dst[5]);


	printf("The source mac address is : ");
	for(i = 0; i < 5 ;i++)
		printf("%02x:", frame.mac_src[i]);
	printf("%02x\n",frame.mac_dst[5]);


	printf("The frame type is : 0x");
	for(i = 0; i < 2 ;i++)
		printf("%02x", frame.eth_type[i]);
	printf("\n");


	if(frame.ip_vers_ihl == 0x45)
	printf("IP version is : 4 \n");


	printf("ID is: 0x");
	for(i = 0; i < 2; i++){
		printf("%02x",frame.ip_id[i]);
	}printf("\n");


	printf("Fragment offset is : 0x");
	for(i = 0; i < 2; i++){
		printf("%02x",frame.ip_flags_frag_offset[i]);
	}printf("\n");


	printf("Time to live is : %d \n",frame.ip_ttl);
	

	printf("IP Checksum is : 0x");
	for(i = 0; i < 2; i++){
		printf("%02x",frame.ip_checksum[i]);
	}printf("\n");

	printf("Source ip is : ");
	for(i = 0; i < 3; i++ ){
		printf("%d.",frame.ip_src[i]);
	}printf("%d\n",frame.ip_src[3]);

	printf("Destination ip is : ");
	for(i = 0; i < 3; i++ ){
		printf("%d.",frame.ip_dst[i]);
	}printf("%d\n",frame.ip_dst[3]);
	

	printf("TCP Source Port is : %d\n",frame.tcp_srcport);
	printf("TCP Destination Port is : %d\n",frame.tcp_dstport);
	

	printf("TCP Sequence Number is : 0x");
	for(i = 0; i < 4; i++)
		printf("%02x",frame.tcp_seq[i]); 
	printf("\n");

	printf("TCP acknowledgement Number is : 0x");
	for(i = 0; i < 4; i++)
		printf("%02x",frame.tcp_ack[i]); 
	printf("\n");

	printf("TCP flag is : 0x");
	for(i = 0; i < 2; i++)
		printf("%02x", frame.tcp_flags[i]);
	printf("\n");

	printf("TCP offset is : %d bytes\n", frame.tcp_offset);

	printf("Windows size value is : %d\n", frame.tcp_window_size_value);
	
	printf("TCP Checksum is : 0x");
	for(i = 0; i < 2; i++)
		printf("%02x", frame.tcp_checksum[i]);
	printf("\n");
	
	printf("TCP options are : 0x");
	for(i = 0; i < frame.tcp_offset-20; i++)
		printf("%02x",frame.tcp_options[i]);
	printf("\n");

	
	return EXIT_SUCCESS;
}
