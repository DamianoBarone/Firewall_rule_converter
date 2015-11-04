#include <stdint.h>
struct packed_header
{
    uint32_t src_ip, dest_ip;
    uint16_t src_port, dest_port;
    uint8_t prot;
};
int check(struct packed_header *pkt);
