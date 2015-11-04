#include "packet.h"
#include <stdio.h>
int main()
{
	struct packed_header pak;
	pak.src_ip=87;
	pak.dest_ip=97;
	pak.src_port=77;
	pak.dest_port=80;
	pak.prot=0;
	printf("%d\n", check(&pak));
	return 0;
}
