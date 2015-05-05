/**
 * \file parser.c
 * \brief HTTP Parser
 */

#include "parser.h"

//Doesn't work with frames with options

// ipv4 exemple  : ./parser 74 e8be812a071a448a5b409a0008004500003cbe004000400642a2c0a801078168f7019c0c00506fe55bc400000000a00272104d890000020405b40402080a0082e5c40000000001030307
// ipv6 exemple : ./parser 90 333300000016448a5b43613f86dd6000000000240001fe8000000000000079c99880425ba9dbff0200000000000000000000000000163a000502000001008f00737e0000000102000000ff02000000000000000000000000000c
int main(int argc, char* argv[]){
	
	//input frame  test
	struct frame frame;
	if (argc !=3){
		printf("Invalid number of arguments");
		return EXIT_FAILURE;
	}
	u_char* f = NULL;
	f = malloc(2 * atoi(argv[1]) * sizeof(u_char));
	
	memcpy( f, argv[2], 2 * atoi(argv[1]) ) ;

//"structuring the frame"
	int i;
	//mac addresses
	for(i = 0; i < 12; i++){
		frame.mac_dst[i] = f[i];
		frame.mac_src[i] = f[12+i];
	}
	//1st test : is the frame a ip frame ?
	bool type4Bool = true;
	bool type6Bool = true;
	u_char eth_type4[] = {'0','8','0','0'}; // if ipv4 frame, type is 0800
	u_char eth_type6[] = {'8','6','d','d'}; // if ipv6 frame, type is 86dd
	for(i = 0; i < 4; i++){
		frame.eth_type[i] = f[24+i];
		if (frame.eth_type[i] != eth_type4[i])
			type4Bool = false;
		if (frame.eth_type[i] != eth_type6[i])
			type6Bool = false;
	}
	if(!type4Bool & !type6Bool){
		printf("\nIt is not an ip frame\n");
		return EXIT_FAILURE;
	}

	//2nd test : is the version of ip 4 or 6 ?
	frame.ip_vers = f[28];
	if(frame.ip_vers != '4' && frame.ip_vers !='6')
	{
		printf("Unvalid ip version\n");
		return EXIT_FAILURE;
	}
	// We distinguish two cases : ipv4 & ipv6
	if(frame.ip_vers == '4'){
		//ihl4
		frame.ihl4 = f[29];
		//type of service
		frame.ip_tos[0]=f[30];
		frame.ip_tos[1]=f[31];
		//length of ip packet 
		for(i = 0; i < 4; i++)
			frame.ip_len[i] = f[32+i];
		//id
		for(i = 0; i < 4; i++)
			frame.ip_id[i] = f[36+i];
		//flags : 3bits et fragments offset : 13 bits
		for(i = 0; i < 4; i++)
			frame.ip_flags_frag_offset[i] = f[40+i];
		//ttl
		for(i = 0; i < 2; i++)
			frame.ip_ttl[i] = f[44+i];
		//protocol, 3rd test : if protocol is tcp, ip_proto is 06
		bool protoBool = true;
		u_char ipproto[] = {'0','6'};
		for(i = 0; i  < 2; i++){
			frame.ip_proto[i] = f[46+i];
			if(frame.ip_proto[i] != ipproto[i])
				protoBool = false;
		}
		if(!protoBool){
			printf("\nThe protocol isn't tcp\n");
			return EXIT_FAILURE;
		}
		//checksum
		for(i = 0; i < 4; i++)
			frame.ip_checksum[i] = f[48+i];
		
		// ip source & destinataire
		for(i=0; i < 8; i++){
			frame.ip_src[i] = f[52+i];
			frame.ip_dst[i] = f[60+i]; 
		}
		//Options
		//There is an option field if ihl != 5 (!= 20 bytes)
		//
		// TO DO
		//
	}
	else{ //frame.ip_vers == '6'
		for(i = 0; i < 8; i++)
			frame.ipv6_class_flow[i] = f[28+i];
		for(i = 0; i < 4; i++)
			frame.ipv6_plen[i] = f[36+i];
		//protocol, 3rd test : if protocol is tcp, ip_proto is 06
		bool protoBool = true;
		u_char ipproto[] = {'0','6'};
		for(i = 0; i < 2; i++){
			frame.ipv6_nxt[i] = f[40+i];
			if(frame.ip_proto[i] != ipproto[i])
				protoBool = false;
		}
		if(!protoBool){
			printf("\nThe protocol isn't tcp\n");
			return EXIT_FAILURE;
		}

		for(i = 0; i < 2 ; i++)
			frame.ipv6_hlim[i] = f[42+i];
		for(i = 0; i < 32 ; i++){
			frame.ipv6_src[i] = f[44+i];
			frame.ipv6_dst[i] = f[76+i];
		}
	}
	
	// TCP

	



//Test 
	printf("\nLa mac du destinataire est : ");
	for(i = 0; i < 12 ;i++)
		printf("%c", frame.mac_dst[i]);
	printf("\n");

	printf("La mac source est : ");
	for(i = 0; i < 12 ;i++)
		printf("%c", frame.mac_src[i]);
	printf("\n");

	printf("Le type de la frame est : ");
	for(i = 0; i < 4 ;i++)
		printf("%c", frame.eth_type[i]);
	printf("\n");

	printf("La version de l'ip est : %c\n", frame.ip_vers);

	//si ivp4
	if(frame.ip_vers == '4'){
		printf("L'id est: ");
		for(i = 0; i < 4; i++){
			printf("%c",frame.ip_id[i]);
		}printf("\n");


		printf("Le champ flags et position fragment vaut : ");
		for(i = 0; i < 4; i++){
			printf("%c",frame.ip_flags_frag_offset[i]);
		}printf("\n");

		printf("La ttl est de : ");
		for(i = 0; i < 2; i++){
			printf("%c",frame.ip_ttl[i]);
		}printf("\n");

		printf("Le checksum est : ");
		for(i = 0; i < 4; i++){
			printf("%c",frame.ip_checksum[i]);
		}printf("\n");

		printf("L'ip source est : ");
		for(i = 0; i < 8; i++ ){
			printf("%c",frame.ip_src[i]);
		}printf("\n");

		printf("L'ip destinataire est : ");
		for(i = 0; i < 8; i++ ){
			printf("%c",frame.ip_dst[i]);
		}printf("\n");
	}
	//si ipv6
	else{ 
		printf("Le champ class et flow est : ");
		for(i = 0; i < 8; i++)
			printf("%c", frame.ipv6_class_flow[i]);
		printf("\n");

		printf("La longueur (Payload Length) est : ");
		for(i = 0; i < 4; i++)
			printf("%c", frame.ipv6_plen[i]);
		printf("\n");

		printf("L'entete suivante est : ");
		for(i = 0; i < 2; i++)
			printf("%c", frame.ipv6_nxt[i]);
		printf("\n");

		printf("Le saut maximum est : ");
		for(i = 0; i < 2; i++)
			printf("%c", frame.ipv6_hlim[i]);
		printf("\n");

		printf("L'adresse source est : ");
		for(i = 0; i < 32; i++)
			printf("%c", frame.ipv6_src[i]);
		printf("\n");

		printf("L'adresse du destinataire est :");
		for(i = 0; i < 32; i++)
			printf("%c", frame.ipv6_dst[i]);
		printf("\n");
	}
	return EXIT_SUCCESS;
}