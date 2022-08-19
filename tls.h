#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <md5.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// https://www.ibm.com/docs/en/zos/2.3.0?topic=programming-cipher-suite-definitions
#define MAX_CIPHERS 256
#define MAX_JA3_STRLEN 256
#define PARSE_UINT16(data, pos) ((data[pos] << 8) + data[pos+1])

typedef struct {
	uint16_t ch_version;
	uint16_t ciphers[MAX_CIPHERS];
	size_t ciphers_len;
	uint16_t extensions[MAX_CIPHERS];
	size_t extensions_len;
	uint16_t ecs[MAX_CIPHERS];
	size_t ecs_len;
	uint8_t pf;
	bool pf_set;
} ja3info_t;

typedef struct ja3hash {
	uint8_t sum[16];
} ja3hash_t;

/**
 * returns the number of bytes parsed in the cipher section
 */
size_t parse_ciphers(const uint8_t* data, size_t data_len, ja3info_t* info);

size_t parse_extensions(const uint8_t* data, size_t data_len, ja3info_t* info);

/**
 * Assumes info has been cleared (set to 0)
 *
 * Return values:
 * -1 for bad parameters
 * -2 for invalid tls record (e.g. not client hello)
 */
int parse_tls_client_hello(const uint8_t* data, size_t data_len, ja3info_t* info);

int parse_tls_packet(struct iphdr* pkt, ja3info_t* info);

/**
 * Assumes buf will be big enough, returns -2 otherwise
 */
int interpolate(const uint16_t* data, size_t data_len, char* buf, char interpolator);

int ja3_str(const ja3info_t* info, char* buf);

ja3hash_t ja3_sum(const char* ja3str);
