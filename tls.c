#include "tls.h"

size_t parse_ciphers(const uint8_t* data, size_t data_len, ja3info_t* info) {
	size_t cipher_len = PARSE_UINT16(data, 0);
	size_t offset = 2;
	info->ciphers_len = 0;
	for (int i = 0; i < cipher_len && i < data_len; i += 2) {
		uint16_t cipher = PARSE_UINT16(data, offset + i);
		if ((cipher & 0x0f0f) == 0x0a0a) {
			continue;
		}
		info->ciphers[info->ciphers_len++] = cipher;
	}
	return cipher_len + 2;
}

size_t parse_extensions(const uint8_t* data, size_t data_len, ja3info_t* info) {
	if (!data || !info) {
		return -1;
	}
	size_t offset = 0;
	size_t exts_len = PARSE_UINT16(data, offset);
	size_t ex_offset = 0, ec_offset = 0, ec_pf_offset = 0;
	info->extensions_len = 0;
	info->ecs_len = 0;
	offset += 2;
	// offset now points to the extension data
	// i points to the start of the next extension
	int i = 0;
	while (i < exts_len) {
		uint16_t ext_type = PARSE_UINT16(data, offset + i);
		// length of the current extension
		size_t ext_len = PARSE_UINT16(data, offset + i + 2);
		// don't include GREASE extensions
		if ((ext_type & 0x0f0f) != 0x0a0a) {
			info->extensions[info->extensions_len++] = ext_type;
		}
		// check for an EC or EC point format extension
		switch (ext_type) {
			// EC extension
			case 0x000a:
				for (int j = 6; j < ext_len + 4 - 1; j += 2) {
					uint16_t ec = PARSE_UINT16(data, offset + i + j);
					if ((ec & 0x0f0f) == 0x0a0a) {
						continue;
					}
					info->ecs[info->ecs_len++] = ec;
				}
				break;
			// EC point format extension
			case 0x000b:
				info->pf = data[offset + i + 5];
				info->pf_set = true;
		}
		i += ext_len + 4;
	}
	return exts_len + 2;
}

int parse_tls_client_hello(const uint8_t* data, size_t data_len, ja3info_t* info) {
	if (!info) {
		return -1;
	}
	// if the packet is not a handshake record
	// or if the handshake message type is not a client hello
	if (data[0] != 0x16 || data[5] != 1) {
		return -2;
	}
	// size of the TLS record
	size_t rec_len = PARSE_UINT16(data, 3);
	// check if the record does not fit in this packet
	// because tcp does not maintain message boundaries
	if (rec_len > data_len - 5) {
		fprintf(stderr, "cannot currently handle records across packets");
		return -3;
	}
	info->ch_version = PARSE_UINT16(data, 9);
	size_t sessid_len = data[43];
	size_t offset = 44 + sessid_len;
	offset += parse_ciphers(&data[offset], data_len - offset, info);
	// skip compression methods
	offset += 2;
	offset += parse_extensions(&data[offset], data_len - offset, info);
	return 0;
}


int parse_tls_packet(struct iphdr* pkt, ja3info_t* info) {
	if (!pkt || !info) {
		return -1;
	}
	struct tcphdr* tcp = (struct tcphdr*) (((uint8_t*) pkt) + (pkt->ihl * 4));
	uint8_t* tls = ((uint8_t*) tcp) + (tcp->doff * 4);
	if (parse_tls_client_hello(tls, pkt->tot_len - (4*(pkt->ihl + tcp->doff)), info) < 0) {
		//fprintf(stderr, "failed to parse tls info\n");
	}
	return pkt->tot_len * 4;
}

int interpolate(const uint16_t* data, size_t data_len, char* buf, char interpolator) {
	if (!data || !buf) {
		return -1;
	}
	size_t bufidx = 0;
	for (size_t i = 0; i < data_len; i++) {
		char ascii_int[8] = {0};
		size_t read = snprintf(ascii_int, 8, "%d", data[i]);
		strncpy(&buf[bufidx], ascii_int, 8);
		bufidx += read;
		if (i < data_len - 1) {
			buf[bufidx++] = interpolator;
		}
	}
	return 0;
}

/**
 * Truncates the ja3 string to 255 characters
 * TODO don't do that
 */
int ja3_str(const ja3info_t* info, char* buf) {
	if (!info || !buf) {
		return -1;
	}
	char ja3ciphers[MAX_JA3_STRLEN] = {0};
	interpolate(info->ciphers, info->ciphers_len, ja3ciphers, '-');
	char ja3exts[MAX_JA3_STRLEN] = {0};
	interpolate(info->extensions, info->extensions_len, ja3exts, '-');
	char ja3ecs[MAX_JA3_STRLEN] = {0};
	interpolate(info->ecs, info->ecs_len, ja3ecs, '-');

	char ja3str[MAX_JA3_STRLEN] = {0};
	if (info->pf_set) {
		snprintf(buf, MAX_JA3_STRLEN, "%d,%s,%s,%s,%d", info->ch_version, ja3ciphers, ja3exts, ja3ecs, info->pf);
	} else {
		snprintf(buf, MAX_JA3_STRLEN, "%d,%s,%s,%s,", info->ch_version, ja3ciphers, ja3exts, ja3ecs);
	}
	return 0;
}

ja3hash_t ja3_sum(const char* ja3str) {
	uint8_t res[16];
	MD5_CTX ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, (uint8_t*) ja3str, strlen(ja3str));
	MD5Final(res, &ctx);
	ja3hash_t h;
	memcpy(h.sum, res, sizeof(res));
	return h;
}
