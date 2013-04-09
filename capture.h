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
	cap_thread(pcap_if_t *alldevs, int d_num);
	vector<pkt_info> * get_pkt_list();
	void set_status(bool val);

	public slots:
		int pkt_cap();       // capture function

signals:
		void cap(int);

private:
	pcap_if_t *dev_list;
	pcap_t *adhandle;         // pcap instance
	int dev_num;
	vector<pkt_info> *pkts;
	bool status;

};


#endif