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

		struct pkt_info pkt;
		
		time = header->ts.tv_sec;
		ltime = localtime(&time);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("->pkt_num: %s,%.6d  len:%d\n", timestr, header->ts.tv_usec, header->len);
		
		pkt.ms = header->ts.tv_usec;
		pkt.caplen = header->caplen;
		pkt.len = header->len;

		memcpy(pkt.pkt_data, pkt_data, strlen((char *)pkt_data));

		pkts->push_back(pkt);
		emit cap(pkt_num);
		pkt_num ++;
	}
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }

	return pkt_num;
}
