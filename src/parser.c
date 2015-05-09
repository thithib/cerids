/**
 * \file parser.c
 * \brief HTTP Parser
 */

#include "parser.h"

//Doesn't work with frames with options

int parser(int frame_length, char* f){
	struct frame frame;
	int i;

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
	

	printf("Checksum is : 0x");
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
	
	return EXIT_SUCCESS;
}