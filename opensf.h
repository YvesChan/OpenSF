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
	QStringList * prase_mac(mac_header *mh);
	QStringList * prase_ip(ip_header *ih);
	QStringList * prase_tcp(tcp_header *th);
	QStringList * prase_udp(udp_header *uh);
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
	// char ans[10], str[20];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
	vector<pkt_info> *pkts;
	int dev_num;
	// vector<pkt_info>::iterator iter
	vector<pkt_info>::size_type index;


	private slots:
		void start_cap();
		void stop_cap();
		void show_pkt(int row);

};

#endif // OPENSF_H
