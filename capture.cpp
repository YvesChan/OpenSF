#include "capture.h"

cap_thread::cap_thread(pcap_if_t *alldevs, int d_num)
{
	dev_list = alldevs;
	dev_num = d_num;
	pkts = new vector<pkt_info>();
}

void cap_thread::set_status(bool val)
{
	status = val;
}

vector<pkt_info> * cap_thread::get_pkt_list()
{
	return pkts;
}

int cap_thread::pkt_cap()
{
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;     // packet buffer
	struct tm *ltime;
	time_t time;
	char timestr[16];

	int res;
	int i = 1;   // start from 1
	int pkt_num = 0;   // packet's number

	// jump to selected device
	for(dev = dev_list; i != dev_num; dev = dev->next, i++);

	// open device
	if((adhandle = pcap_open(dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
		fprintf(stderr, "\nUnable to open adapter: %s\n", dev->name);
		return -1;
	}

	while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
		if(!status){
			printf("Stop capturing\n");
			break;
		}

		if(res == 0){
			continue;   // time out
		}
		
		time = header->ts.tv_sec;
		ltime = localtime(&time);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("%d: %s,%.6d  len:%d \n", pkt_num, timestr, header->ts.tv_usec, header->len);

		struct pkt_info pkt;
		strcpy(pkt.timestr, timestr);
		pkt.ms = header->ts.tv_usec;
		pkt.caplen = header->caplen;
		pkt.len = header->len;

		memcpy(pkt.pkt_data, pkt_data, pkt.caplen + 1);

		pkts->push_back(pkt);
		emit cap(pkt_num);    // test vector
		pkt_num ++;


		//mac_header *mh = (mac_header *)pkt_data;
		//ip_header *ih = (ip_header *)(pkt_data + 14);
		//u_short ftype = ntohs(mh->type);

		//switch(ftype){     // EtherType, see more:http://en.wikipedia.org/wiki/Ethertype
		//case 0x0806:     // ARP packet
		//	printf("ARP\n");
		//	break;
		//case 0x0800:     // IPv4 packet
		//	printf("type:%d ", ih->proto);
		//	if((ih->proto ^ 0x06) == 0){
		//		printf("TCP :");
		//	}
		//	else if((ih->proto ^ 0x11) == 0){
		//		printf("UDP :");
		//	}
		//	else printf("Unknown :");
		//	
		//	printf("      src:%d.%d.%d.%d ", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		//	printf("dst:%d.%d.%d.%d \n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
		//	break;
		//default:
		//	printf("Unknown\n");
		//}
	}
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }

	return pkt_num;
}
