#include "packet.h"

int level_3_1(struct packed_header *pkt) {
	uint32_t value=pkt->dest_ip;
	if (value >= 2175271169 && value <= 2192048385)
		return 1;
	return 1;
}

int level_3_2(struct packed_header *pkt) {
	uint32_t value=pkt->dest_ip;
	if (value >= 3366453505 && value <= 4205314305)
		return 1;
	return 1;
}

int level_3_3(struct packed_header *pkt) {
	uint32_t value=pkt->dest_ip;
	if (value >= 2024276225 && value <= 2192048385)
		return 0;
	return 1;
}

int level_3_4(struct packed_header *pkt) {
	uint32_t value=pkt->dest_ip;
	if (value >= 3232235777 && value <= 3232235777)
		return 1;
	return 1;
}

int level_3_5(struct packed_header *pkt) {
	uint32_t value=pkt->dest_ip;
	if (value >= 4289200385 && value <= 4289200385)
		return 1;
	return 1;
}

int level_3_6(struct packed_header *pkt) {
	uint32_t value=pkt->dest_ip;
	if (value >= 3366453505 && value <= 3701997825)
		return 0;
	return 1;
}

int level_2_1(struct packed_header *pkt) {
	uint16_t value=pkt->dest_port;
	if (value >= 2500 && value <= 5000)
		return level_3_1(pkt);
	return 1;
}

int level_2_2(struct packed_header *pkt) {
	uint16_t value=pkt->dest_port;
	if (value >= 2000 && value <= 2000)
		return level_3_2(pkt);
	return 1;
}

int level_2_3(struct packed_header *pkt) {
	uint16_t value=pkt->dest_port;
	if (value >= 8500 && value <= 9000)
		return level_3_3(pkt);
	return 1;
}

int level_2_4(struct packed_header *pkt) {
	uint16_t value=pkt->dest_port;
	if (value >= 5001 && value <= 6000)
		return level_3_4(pkt);
	return 1;
}

int level_2_5(struct packed_header *pkt) {
	uint16_t value=pkt->dest_port;
	if (value >= 6500 && value <= 7000)
		return level_3_5(pkt);
	return 1;
}

int level_2_6(struct packed_header *pkt) {
	uint16_t value=pkt->dest_port;
	if (value >= 7500 && value <= 8000)
		return level_3_6(pkt);
	return 1;
}

int level_1_1(struct packed_header *pkt) {
	uint32_t value=pkt->src_ip;
	if (value >= 3366453505 && value <= 3371041025)
		return level_2_1(pkt);
	return 1;
}

int level_1_2(struct packed_header *pkt) {
	uint32_t value=pkt->src_ip;
	if (value >= 3233022209 && value <= 3233677569)
		return level_2_2(pkt);
	return 1;
}

int level_1_3(struct packed_header *pkt) {
	uint32_t value=pkt->src_ip;
	if (value >= 4205314305 && value <= 4205314305)
		return level_2_3(pkt);
	return 1;
}

int level_1_4(struct packed_header *pkt) {
	uint32_t value=pkt->src_ip;
	if (value >= 3232301313 && value <= 3232366849)
		return level_2_4(pkt);
	return 1;
}

int level_1_5(struct packed_header *pkt) {
	uint32_t value=pkt->src_ip;
	if (value >= 4289200385 && value <= 4289200385)
		return level_2_5(pkt);
	return 1;
}

int level_1_6(struct packed_header *pkt) {
	uint32_t value=pkt->src_ip;
	if (value >= 1688731905 && value <= 2024276225)
		return level_2_6(pkt);
	return 1;
}

int level_0_1(struct packed_header *pkt) {
	uint16_t value=pkt->src_port;
	if (value >= 0 && value <= 200)
		return level_1_1(pkt);
	if (value >= 201 && value <= 400)
		return level_1_2(pkt);
	if (value >= 801 && value <= 4000)
		return level_1_3(pkt);
	return 1;
}

int level_0_2(struct packed_header *pkt) {
	uint16_t value=pkt->src_port;
	if (value >= 500 && value <= 600)
		return level_1_4(pkt);
	if (value >= 601 && value <= 700)
		return level_1_5(pkt);
	if (value >= 701 && value <= 802)
		return level_1_6(pkt);
	return 1;
}

int check(struct packed_header *pkt) {
	uint8_t value=pkt->prot;
	if (value >= 0 && value <= 0)
		return level_0_1(pkt);
	if (value >= 1 && value <= 1)
		return level_0_2(pkt);
	return 1;
}

