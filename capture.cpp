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
		sprintf(errbuf, "Unable to open adapter: %s", dev->name);
		emit cap(-1);
		return -1;
	}

	// detect Ethernet
	if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
		sprintf(errbuf,"This program works only on Ethernet networks.");
		emit cap(-2);
		return -2;
    }

	// get the device's first address
	if(dev->addresses != NULL)
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else 
		netmask = 0xffffff;

	// compile filter
	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0 )
	{
		sprintf(errbuf,"Unable to compile the packet filter. Check the syntax.");
		emit cap(-3);
		return -3;
	}

	// set filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
		sprintf(errbuf,"Error while setting the filter.");
		emit cap(-4);
		return -4;
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
		sprintf(errbuf, "Error reading the packets: %s", pcap_geterr(adhandle));
		emit cap(-5);
		return -5;
    }

	return pkt_num;
}

cap_thread::~cap_thread()
{
	pcap_close(adhandle);
	delete pkts;
}