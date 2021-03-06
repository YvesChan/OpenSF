#ifndef CAPTURE_H
#define CAPTURE_H

#include <QObject>
#include <vector>

#include "opensf.h"
#include "pcap.h"
#include "winsock2.h"
#include "lib.h"

using namespace std;

class cap_thread : public QObject
{
	Q_OBJECT

public:
	cap_thread(vector<pkt_info> * pkt_list);
	~cap_thread();
	vector<pkt_info> * get_pkt_list();
	void set_status(bool val);
	void set_devlist(pcap_if_t * dl);
	void set_devnum(int num);
	void set_filter(char *str);
	char errbuf[PCAP_ERRBUF_SIZE];

	public slots:
		int pkt_cap();       // capture function

signals:
		void cap(int);

private:
	pcap_if_t *dev_list;      // devices list passed by main thread
	pcap_t *adhandle;         // pcap instance
	int dev_num;          // current selected dev's index number
	char filter[100];      // filter string
	vector<pkt_info> *pkts;    // packet container
	bool status;

};


#endif