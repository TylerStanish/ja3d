#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "tls.h"

static int cb(const struct nlmsghdr* hdr, void* sock) {
	// Allocate space for the netlink message
	char buf[MNL_SOCKET_BUFFER_SIZE];
	// Allocate space to hold the parsed attributes belonging to this netlink message
	struct nlattr* attrs[NFQA_MAX+1];
	// Can you have more than one attribute of the same type in a single netlink message?
	// nfq_nlmsg_parse assumes you won't
	if (nfq_nlmsg_parse(hdr, attrs) < 0) {
		perror("nfq_nlmsg_parse");
		return MNL_CB_ERROR;
	}
	// To get the queue number, get a pointer to the payload. There is an
	// extra header at the start of the payload where the it can be found
	// https://git.netfilter.org/libmnl/tree/src/nlmsg.c#n40
	struct nfgenmsg* payload = mnl_nlmsg_get_payload(hdr);
	int qnum = payload->res_id;

	struct iphdr* pkt = mnl_attr_get_payload(attrs[NFQA_PAYLOAD]);
	struct in_addr s;
	s.s_addr = pkt->saddr;
	struct in_addr d;
	d.s_addr = pkt->daddr;
	
	char dest_ip[16];
	strcpy(dest_ip, inet_ntoa(d));

	ja3info_t info;
	memset(&info, 0, sizeof(ja3info_t));
	parse_tls_packet(pkt, &info);
	char ja3str[256];
	if (ja3_str(&info, ja3str) < 0) {
		fprintf(stderr, "failed to get ja3 string");
		return MNL_CB_ERROR;
	}
	ja3hash_t res = ja3_sum(ja3str);
	for (int i = 0; i < 16; i++) {
		printf("%02x", res.sum[i]);
	}
	printf("\n");

	// The actual content of the packet
	struct nfqnl_msg_packet_hdr* packet = mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]);

	// Construct the verdict packet to send back to netfilter
	// Reuse buf here. vertictpkt will point to buf
	struct nlmsghdr* verdictpkt = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, qnum);
	nfq_nlmsg_verdict_put(verdictpkt, ntohl(packet->packet_id), NF_ACCEPT);
	if (mnl_socket_sendto(sock, verdictpkt, verdictpkt->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return MNL_CB_ERROR;
	}
	return MNL_CB_OK;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: ja3d <queue number>\n");
		return EXIT_FAILURE;
	}
	int qnum = atoi(argv[1]);
	size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
	char* buf = malloc(sizeof_buf);
	if (!buf) {
		perror("malloc");
		return EXIT_FAILURE;
	}

	struct mnl_socket* sock = mnl_socket_open(NETLINK_NETFILTER);
	if (!sock) {
		perror("mnl_socket_open");
		return EXIT_FAILURE;
	}

	if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return EXIT_FAILURE;
	}

	int portid = mnl_socket_get_portid(sock);

	struct nlmsghdr* hdr;
	// bind the queue number to this socket
	hdr = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, qnum);
	nfq_nlmsg_cfg_put_cmd(hdr, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(sock, hdr, hdr->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return EXIT_FAILURE;
	}

	// copy all packets
	hdr = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, qnum);
	nfq_nlmsg_cfg_put_params(hdr, NFQNL_COPY_PACKET, 0xffff);

	if (mnl_socket_sendto(sock, hdr, hdr->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return EXIT_FAILURE;
	}

	while (true) {
		ssize_t numread = mnl_socket_recvfrom(sock, buf, sizeof_buf);
		if (numread < 0) {
			perror("mnl_socket_recvfrom");
			return EXIT_FAILURE;
		}
		int errbefore = errno;
		int res = mnl_cb_run(buf, numread, 0, portid, cb, sock);
		int errafter = errno;
		if (res == 0) {
			break;
		}
		if (res < 0) {
			perror("mnl_cb_run");
			return EXIT_FAILURE;
		}
	}

	mnl_socket_close(sock);

	return 0;
}
