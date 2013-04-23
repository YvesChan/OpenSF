#include "capture.h"
#include <cstdio>


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

void cap_thread::set_filter(char *str)
{
	strncpy(filter, str, sizeof(filter));
	return;
}

int cap_thread::pkt_cap()
{
	pcap_if_t *dev;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;     // packet buffer
	struct tm *ltime;
	time_t time;
	char timestr[16];
	unsigned int netmask;
	struct bpf_program fcode;

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

	// detect Ethernet
	if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		return -1;
    }

	// get the device's first address
	if(dev->addresses != NULL)
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else 
		netmask = 0xffffff;

	// compile filter
	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// set filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
		fprintf(stderr,"\nError setting the filter.\n");
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
		// printf("%d: %s,%.6d  len:%d \n", pkt_num, timestr, header->ts.tv_usec, header->len);

		struct pkt_info pkt;
		strcpy(pkt.timestr, timestr);
		pkt.ms = header->ts.tv_usec;
		pkt.caplen = header->caplen;
		pkt.len = header->len;

		memcpy(pkt.pkt_data, pkt_data, pkt.caplen + 1);

		pkts->push_back(pkt);
		emit cap(pkt_num);    // test vector
		pkt_num ++;
	}
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }

	return pkt_num;
}

cap_thread::~cap_thread()
{
	delete pkts;
}