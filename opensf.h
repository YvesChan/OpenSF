#ifndef OPENSF_H
#define OPENSF_H

#include <QtGui/QMainWindow>
#include <vector>

#include "ui_opensf.h"
#include "capture.h"
#include "pcap.h"
#include "lib.h"

using namespace std;

class cap_thread;

class OpenSF : public QMainWindow
{
	Q_OBJECT

public:
	OpenSF(QWidget *parent = 0, Qt::WFlags flags = 0);
	int find_devs();
	QTreeWidgetItem * prase_mac(mac_header *mh);
	QTreeWidgetItem * prase_ip(ip_header *ih);
	QTreeWidgetItem * prase_tcp(tcp_header *th);
	QTreeWidgetItem * prase_udp(udp_header *uh);
	QTreeWidgetItem * prase_arp(arp_payload *ap);
	QTreeWidgetItem * prase_icmp(icmp_payload *ic);
	QTreeWidgetItem * prase_dns(dns_payload *dp);

	void judge_proto(int port, QString *str, QString def);
	~OpenSF();
	// friend class cap_thread;

	public slots:
		void display(int pkt_num);

private:
	Ui::OpenSFClass ui;
	QComboBox *combo_box_devs;
	QComboBox *combo_box_filter;
	QActionGroup *act_grp;
	QAction *act_start;
	QAction *act_stop;
	QAction *act_apply;
	QAction *act_clear;
	cap_thread *capture;
	QThread *thread_mgr;

	pcap_if_t *alldevs;        // device list
	pcap_if_t *d;
	vector<pkt_info> *pkts;
	int dev_num;
	QString filter;
	vector<pkt_info>::size_type index;


	private slots:
		void start_cap();
		void stop_cap();
		void show_pkt(int row);
		void check_filter();
		void apply_filter();
		void clear_filter();

};

#endif // OPENSF_H
