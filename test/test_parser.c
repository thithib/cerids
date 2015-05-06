#include "../src/parser.h"

// ipv4 exemple  : parser(74,e8be812a071a448a5b409a0008004500003cbe004000400642a2c0a801078168f7019c0c00506fe55bc400000000a00272104d890000020405b40402080a0082e5c40000000001030307)
// ipv6 exemple : parser(90,333300000016448a5b43613f86dd6000000000240001fe8000000000000079c99880425ba9dbff0200000000000000000000000000163a000502000001008f00737e0000000102000000ff02000000000000000000000000000c)


int main(int argc, char* argv[]){
if (argc !=3){
		printf("Invalid number of arguments");
		return EXIT_FAILURE;
	}
	parser(atoi(argv[1]), argv[2]);
	return EXIT_SUCCESS;
}