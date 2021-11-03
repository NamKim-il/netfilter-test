#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define  MAX_HOST 128
#define  METHOD_LEN_MAX 9
static char HTTP_METHOD[][METHOD_LEN_MAX]={"GET","HEAD","POST","PUT","DELETE","CONNECT","OPTONS","TRACE","PATCH"};

char target[MAX_HOST];

bool check_ipv4(unsigned char* data)
{
	struct libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*) data;
	if(ipv4_hdr->ip_v == 4 && ipv4_hdr->ip_p == IPPROTO_TCP) return true;
	else return false;
}

bool check_http_host(unsigned char* data)
{
	struct libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*) data;
	struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(data + (ipv4_hdr->ip_hl<<2));
	char* payload = (char*)tcp_hdr+(tcp_hdr->th_off<<2);

	bool isHTTP = false;

	for(int i=0; i < sizeof(HTTP_METHOD)/METHOD_LEN_MAX ; i++)
	{
		if(!strncmp(HTTP_METHOD[i], payload, strlen(HTTP_METHOD[i]))) {
			isHTTP = true;
			break;
		}
	}

	if(!isHTTP) return false;
	
	return strstr(payload, target);
}

bool check_pkt(struct nfq_data *tb, u_int32_t *id)
{
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
	unsigned char *data;

	if(ph) *id = ntohl(ph->packet_id);

	int size = nfq_get_payload(tb, &data);
	
	return check_ipv4(data)&&check_http_host(data);
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id;
	if(check_pkt(nfa,&id)) {
		puts("Drop");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void usage(){
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test test.gilgil.net\n");
	return;
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	if(argc!=2) {
		usage();
		return -1;
	}

	printf("Target Host : %s\n\n", argv[1]);
	
	strcat(target, "Host: ");
	strncat(target, argv[1],strlen(argv[1]));
	strcat(target, "\r\n");

	puts(target);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

