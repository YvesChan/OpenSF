#ifndef LIB_H
#define LIB_H


// data structure definition
struct pkt_info{
	char timestr[18];      // here note to be a little bigger
	int ms;
	unsigned int caplen;          // actualy capture length
	unsigned int len;             // what it should be 
	u_char pkt_data[1514];            // the max length of Ethernet frame
};

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
    u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char  tos;            // ��������(Type of service) 
    u_short tlen;           // �ܳ�(Total length) 
    u_short identification; // ��ʶ(Identification)
    u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    u_char  ttl;            // ���ʱ��(Time to live)
    u_char  proto;          // Э��(Protocol)
    u_short crc;            // �ײ�У���(Header checksum)
    ip_address  saddr;      // Դ��ַ(Source address)
    ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)
    u_int   op_pad;         // ѡ�������(Option + Padding)
}ip_header;

/* UDP header : 8 bytes */
typedef struct udp_header{
    u_short sport;          // Դ�˿�(Source port)
    u_short dport;          // Ŀ�Ķ˿�(Destination port)
    u_short len;            // UDP���ݰ�����(Datagram length)
    u_short crc;            // У���(Checksum)
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


#endif