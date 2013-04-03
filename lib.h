#include "pcap.h"
#include "winsock2.h"
#include <string>
using namespace std;

// data structure definition

typedef struct dev_list{
	dev_list *next;
	char name[50];
}dev_list;

/* 14 bytes MAC address */
typedef struct mac_header{
	u_char dst[6];			 // destination mac address
	u_char src[6];			 // source mac address
	u_short type;           // frame type
}mac_header;

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header : 20 bytes*/
typedef struct ip_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service) 
    u_short tlen;           // 总长(Total length) 
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP header : 8 bytes */
typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

/* TCP header : 20 bytes*/
typedef struct tcp_header{
	u_short sport;
	u_short dport;
	u_int seqnum;         // sequence number
	u_int acknum;         // acknowledge number
	u_short hl_flag;      // header length & 6 bit flags
	u_short wsize;        // window size
	u_short crc;          // checksum
	u_short urgp;         // urgent pointer
	u_int op_pad;         // optional
}tcp_header;


// var defines  ----------------------
pcap_if_t *alldevs;
pcap_if_t *d;
pcap_t *adhandle;
int i=0, n;
char ans[10], str[20];
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fcode;


// function definition --------------------

// devices provider API
dev_list* find_devs(){
	int fir = 0, las = 0;
	dev_list *dlist = new dev_list;
	dev_list *dl = dlist;
	/* get local devices list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1){
		// fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
       return NULL;
	}

    /* print devices list */
    for(d = alldevs; d != NULL; d = d->next, dl = dl->next)
    {
       // printf("%d. %s", ++i, d->name);
		if (d->description){
			string dev_name(d->description);
			fir = dev_name.find_first_of("\'");
			las = dev_name.find_last_of("\'");
			strncpy(dl->name, dev_name.substr(fir + 1, las - fir - 1).c_str(), 50);   // note substr()'s calculation
		}
       else
		   strcpy(dl->name, "unknown device");
		
		if(d->next != NULL) 
			dl->next = new dev_list;
		else {
			dl->next = NULL;
			break;
		}
    }
    
	if (strlen(dlist->name) == 0)
    {
        strcpy(errbuf, "No interfaces found! Make sure WinPcap is installed.");
        return NULL;
    }

	return dlist;
}


void ifprint(pcap_if_t *d)
{
	pcap_addr_t *tmp;
	// char ip6str[128];

	/* 设备名(Name) */
	printf("%s\n", d->name);

	/* 设备描述(Description) */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses 
	 * A device might have multiple ip addresses, e.g. ipv4 & ipv6
	 */
	for(tmp = d->addresses; tmp; tmp = tmp->next) {
		printf("\tAddress Family: #%d\n", tmp->addr->sa_family);
  
		switch(tmp->addr->sa_family)
		{
			case AF_INET:    // ipv4
				printf("\tAddress Family Name: AF_INET\n");
				if (tmp->addr)
					printf("\tAddress: %s\n",inet_ntoa(((struct sockaddr_in *)tmp->addr)->sin_addr));
				if (tmp->netmask)
					printf("\tNetmask: %s\n",inet_ntoa(((struct sockaddr_in *)tmp->netmask)->sin_addr));
				if (tmp->broadaddr)
					printf("\tBroadcast Address: %s\n",inet_ntoa(((struct sockaddr_in *)tmp->broadaddr)->sin_addr));
				if (tmp->dstaddr)
					printf("\tDestination Address: %s\n",inet_ntoa(((struct sockaddr_in *)tmp->dstaddr)->sin_addr));
				break;

			case AF_INET6:
				printf("\tAddress Family Name: AF_INET6\n");
				//if (a->addr)
					//printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
				break;

			default:
				printf("\tAddress Family Name: Unknown\n");
				break;
		}
	}
	printf("\n");
}

/* while capture packet, winpcap will invoke this callback function */
void pkt_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data){
	struct tm *ltime;
	time_t time;
	char timestr[16];
	mac_header *mh;
	ip_header *ih;
	tcp_header *th;
	udp_header *uh;
	u_short ftype;      // frame type

	time = pkt_header->ts.tv_sec;
	ltime = localtime(&time);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
	printf("%s,%.6d  len:%d\n", timestr, pkt_header->ts.tv_usec, pkt_header->len);

	// get mac & ip header position
	mh = (mac_header *)pkt_data;
	ih = (ip_header *)(mh + 14);

	printf("   dst:%02X-%02X-%02X-%02X-%02X-%02X src:%02X-%02X-%02X-%02X-%02X-%02X   ", 
		mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5],
		mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
	ftype = ntohs(mh->type);     // change network byte order to host byte order
	// printf("frame type: %x ", ftype);
	switch(ftype){     // EtherType, see more:http://en.wikipedia.org/wiki/Ethertype
		case 0x0800:
			printf("IPv4 packet\n");
			break;
		case 0x0806:
			printf("ARP request/response\n");
			break;
		case 0x86DD:
			printf("IPv6 packet\n");
			break;
		case 0x8863:
			printf("PPPoE Discovery Stage\n");
			break;
		case 0x8864:
			printf("PPPoE Session Stage\n");
			break;
		default:
			printf("Unknown type\n");
	}

}


// set packet filter
int set_filter(pcap_t *p, struct bpf_program *fp, char *filter_str, struct pcap_addr *dev_addr){
	u_int netmask;
	// check datalink layer
	if(pcap_datalink(p) != DLT_EN10MB)
	{
		fprintf(stderr, "\nOnly Ethernet works\n");
		return -1;
	}

	while(dev_addr != NULL){
		if(dev_addr->addr->sa_family != AF_INET){
			dev_addr = dev_addr->next;
			continue;
		}
		netmask = ((struct sockaddr_in *)(dev_addr->netmask))->sin_addr.S_un.S_addr;
		break;
	}
	if(dev_addr == NULL) netmask = 0xffffff;

	if(pcap_compile(p, fp, filter_str, 1, netmask) < 0){
		fprintf(stderr, "\nUnable to compile the packet filter\n");
		return -2;
	}

	if(pcap_setfilter(p, fp) < 0){
		fprintf(stderr, "\nError setting filter\n");
		return -3;
	}

	printf("\nfilter set!\n");
	return 0;
}