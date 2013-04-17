#include <QtGui>
#include <string>
#include <QThread>
#include <iostream>

#include "pcap.h"
#include "opensf.h"


OpenSF::OpenSF(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	// resize the splitter's position
	QList<int> spli_pos;
	spli_pos.append(220);
	spli_pos.append(180);
	spli_pos.append(111);
	ui.splitter->setSizes(spli_pos);

	// resize tablewidget's rows to fit their content and forbid editing
	// ui.tableWidget->resizeRowsToContents();
	ui.tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

	// readSettings();
	combo_box_devs = new QComboBox(this);
	combo_box_filter = new QComboBox(this);
	act_grp = new QActionGroup(this);
	act_start = new QAction("Start", act_grp);
	act_stop = new QAction("Stop", act_grp);
	act_apply = new QAction("Apply", this);
	act_clear = new QAction("Clear", this);

	act_grp->addAction(act_start);
	act_grp->addAction(act_stop);
	combo_box_filter->setEditable(true);


	act_start->setCheckable(true);
	act_stop->setCheckable(true);
	act_grp->setExclusive(true);   // action group Exclusive: Only one action can be checked

	// initial Devices list
	int ret = find_devs();
	if(ret == 0){
		QMessageBox::information(this, "OpenSF", "No Devices Found");
	}
	if(ret == -1){
		QMessageBox::information(this, "OpenSF", "Error in Finding Devices");
		exit(-1);
	}

	ui.mainToolBar->addWidget(combo_box_devs);
	ui.mainToolBar->addAction(act_start);
	ui.mainToolBar->addAction(act_stop);

	ui.mainToolBar->addSeparator();

	ui.mainToolBar->addWidget(combo_box_filter);
	ui.mainToolBar->addAction(act_apply);
	ui.mainToolBar->addAction(act_clear);

	// configure tablewidget style
	ui.tableWidget->verticalHeader()->setVisible(false);     // Disable the row header
	ui.tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);    // select the whole row
	ui.tableWidget->setColumnWidth(0, 40);
	ui.tableWidget->setColumnWidth(1, 120);
	ui.tableWidget->setColumnWidth(2, 140);
	ui.tableWidget->setColumnWidth(3, 140);
	ui.tableWidget->setColumnWidth(4, 60);
	ui.tableWidget->setColumnWidth(5, 55);
	ui.tableWidget->setColumnWidth(6, 200);

	connect(act_start, SIGNAL(triggered()), this, SLOT(start_cap()));
	connect(act_stop, SIGNAL(triggered()), this, SLOT(stop_cap()));
	connect(ui.tableWidget, SIGNAL(cellClicked(int, int)), this, SLOT(show_pkt(int)));


	thread_mgr = new QThread(this);
	index = 0;    // pkt_num index initial 
}

// find devices and display
int OpenSF::find_devs()
{
	int fir = 0, las = 0;
	int count = 0;         // amount of devices

	/* get local devices list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1){
		// fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
       return -1;
	}

	combo_box_devs->addItem("--Select device--");
    /* print devices list */
    for(d = alldevs; d != NULL; d = d->next)
    {
		char dev[30];          // part of dev name
		if (d->description){
			string dev_name(d->description);
			fir = dev_name.find_first_of("\'");
			las = dev_name.find_last_of("\'");
			strncpy(dev, dev_name.substr(fir + 1, las - fir - 1).c_str(), 30);   // note substr()'s calculation
		}
       else
		   strcpy(dev, "unknown device");

		combo_box_devs->addItem(dev);
		count ++;
	}

	return count;
}


void OpenSF::start_cap()
{
	// clear the table content before start a new capture
	if(ui.tableWidget->rowCount() != 0){
		QMessageBox msg;
		msg.setText("Start a new capture?");
		msg.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
		msg.setDefaultButton(QMessageBox::Ok);

		if(msg.exec() == QMessageBox::Ok){
			// reverse delete row contents
			ui.tableWidget->clearContents();
			for(int i = ui.tableWidget->rowCount() - 1; i >= 0; i --){
				ui.tableWidget->removeRow(i);
			}
			capture->deleteLater();    // delete old capture instance, especially for *pkts
		}
		else return;
	}

	// start a capture
	int dev_num = combo_box_devs->currentIndex();
	if(dev_num == 0){
		QMessageBox::information(this, "OpenSF", "Please select a network interface");
		return;
	}

	capture = new cap_thread(alldevs, dev_num);
	capture->set_status(true);
	pkts = capture->get_pkt_list();     // get pkt_list address

	QObject::connect(thread_mgr, SIGNAL(started()), capture, SLOT(pkt_cap()));
	QObject::connect(capture, SIGNAL(cap(int)), this, SLOT(display(int)));
	// QObject::connect(thread_mgr, SIGNAL(finished()), capture, SLOT(deleteLater()));
	capture->moveToThread(thread_mgr);

	// Starts an event loop, and emits started() signal
	thread_mgr->start();
	
}

void OpenSF::stop_cap()
{
	capture->set_status(false);
	thread_mgr->quit();
	thread_mgr->wait();
	if(thread_mgr->isFinished()){
		cout << "thread finished!\n";
	}
}

// display packet. 
void OpenSF::display(int pkt_num)
{
	char time_stamp[30];
	char src[20];
	char dst[20];
	char pro[10];
	mac_header *mh;
	ip_header *ih;
	unsigned int ip_len;
	tcp_header *th;
	udp_header *uh;
	unsigned short sport, dport;    // source, distination port

	index = (vector<pkt_info>::size_type)pkt_num;
	// printf("%s,%.6d  len:%d\n", (*pkts)[index].timestr, (*pkts)[index].ms, (*pkts)[index].len);
	sprintf(time_stamp, "%s,%.6d", (*pkts)[index].timestr, (*pkts)[index].ms);
	
	// get mac header position
	mh = (mac_header *)(*pkts)[index].pkt_data;
	u_short ftype = ntohs(mh->type);     // frame type, since it's two bytes, it needs to be transformed

	printf("  dst:%02X-%02X-%02X-%02X-%02X-%02X src:%02X-%02X-%02X-%02X-%02X-%02X   ", 
		mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5],
		mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
	printf("frame type: %x\n", ftype);
	cout << endl;

	switch(ftype){     // EtherType, see more:http://en.wikipedia.org/wiki/Ethertype
		case 0x0806:     // ARP packet
			sprintf(src, "%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			sprintf(dst, "%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			strcpy(pro, "ARP");
			break;
		case 0x0800:     // IPv4 packet
			ih = (ip_header *)((u_char*)mh + 14);   // get ip header position
			ip_len = (ih->ver_ihl & 0xf) * 4;      // get ip header's length

			if((ih->proto ^ 0x06) == 0){      // TCP
				th = (tcp_header *)((unsigned char *)ih + ip_len);   // get TCP header position
				sport = ntohs(th->sport);
				dport = ntohs(th->dport);
				if(dport < 1024){
					judge_proto(dport, pro, "TCP");
				}
				else {
					judge_proto(sport, pro, "TCP");
				}
			}
			else if((ih->proto ^ 0x11) == 0){     // UDP
				uh = (udp_header *)((unsigned char *)ih + ip_len);
				sport = ntohs(uh->sport);
				dport = ntohs(uh->dport);
				if(dport < 1024){
					judge_proto(dport, pro, "UDP");
				}
				else {
					judge_proto(sport, pro, "UDP");
				}
			}
			else if((ih->proto ^ 0x01) == 0){
				strcpy(pro, "ICMP");
			}
			else if((ih->proto ^ 0x02) == 0){
				strcpy(pro, "IGMP");
			}
			else strcpy(pro, "Unknown");
			
			sprintf(src, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
			sprintf(dst, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			printf("      src:%d.%d.%d.%d ", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
			printf("dst:%d.%d.%d.%d \n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			break;
		case 0x86DD:       // IPv6
			// TO DO
			sprintf(src, "%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			sprintf(dst, "%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			strcpy(pro, "IPv6");
			break;
		default:
			sprintf(src, "%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			sprintf(dst, "%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			strcpy(pro, "Unknown");
	}

	// add table data
	ui.tableWidget->insertRow(pkt_num);
	ui.tableWidget->setItem(pkt_num, 0, new QTableWidgetItem(QString::number(pkt_num)));
	ui.tableWidget->setItem(pkt_num, 1, new QTableWidgetItem(time_stamp));
	ui.tableWidget->setItem(pkt_num, 2, new QTableWidgetItem(src));
	ui.tableWidget->setItem(pkt_num, 3, new QTableWidgetItem(dst));
	ui.tableWidget->setItem(pkt_num, 4, new QTableWidgetItem(pro));
	ui.tableWidget->setItem(pkt_num, 5, new QTableWidgetItem(QString::number((*pkts)[index].len)));
	
	return;
}

void OpenSF::show_pkt(int row)
{
	index = (vector<pkt_info>::size_type)row;
	QStringList *mac;
	QStringList *ip;
	QStringList *tcp;
	QStringList *udp;
	QTreeWidgetItem *dll;		// data link layer
	QTreeWidgetItem *nl;		// network layer
	QTreeWidgetItem *tl;		// transport layer
	QTreeWidgetItem *payload;	// datagram payload

	// get mac header
	mac_header *mh = (mac_header *)(*pkts)[index].pkt_data;
	mac = prase_mac(mh);

	dll = new QTreeWidgetItem(ui.treeWidget, QStringList(QString("Data Link Layer")));
	for(int i = 0; i < mac->size(); i ++){
		dll->addChild(new QTreeWidgetItem(dll, QStringList(mac->at(i))));
	}
	ui.treeWidget->insertTopLevelItem(0, dll);

	delete mac;
	if(ntohs(mh->type) == 0x0806){
		// TO DO
		// print payload
		return;
	}

	// get ip header
	ip_header *ih = (ip_header *)((u_char*)mh + 14);   // get ip header position
	ip = prase_ip(ih);

	nl = new QTreeWidgetItem(ui.treeWidget, QStringList(QString("Network Layer")));
	for(int i = 0; i < ip->size(); i ++){
		nl->addChild(new QTreeWidgetItem(nl, QStringList(ip->at(i))));
	}
	ui.treeWidget->insertTopLevelItem(1, nl);

	delete ip;
	if(ih->proto == 1 || ih->proto == 2){
		// TO DO
		return;
	}

	// get tcp/udp header 
	if(ih->proto == 6){     // TCP
		tcp_header *th = (tcp_header *)((unsigned char *)ih + (ih->ver_ihl & 0xf) * 4);
		tcp = prase_tcp(th);

		tl = new QTreeWidgetItem(ui.treeWidget, QStringList(QString("Transport Layer")));
		for(int i = 0; i < tcp->size(); i ++){
			tl->addChild(new QTreeWidgetItem(tl, QStringList(tcp->at(i))));
		}
		ui.treeWidget->insertTopLevelItem(2, tl);

		delete tcp;
	}
	else if(ih->proto == 17){    // UDP
		udp_header *uh = (udp_header *)((unsigned char *)ih + (ih->ver_ihl & 0xf) * 4);
		udp = prase_udp(uh);

		tl = new QTreeWidgetItem(ui.treeWidget, QStringList(QString("Transport Layer")));
		for(int i = 0; i < udp->size(); i ++){
			tl->addChild(new QTreeWidgetItem(tl, QStringList(udp->at(i))));
		}
		ui.treeWidget->insertTopLevelItem(2, tl);

		delete udp;
	}

}

QStringList * OpenSF::prase_mac(mac_header *mh)
{
	QStringList *ret = new QStringList();
	u_short ftype = ntohs(mh->type);
	QString src;
	QString dst;
	QString pro;

	src.sprintf("Source: %02X-%02X-%02X-%02X-%02X-%02X", mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
	dst.sprintf("Destination: %02X-%02X-%02X-%02X-%02X-%02X", mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
	pro.sprintf("Type: %04X", ftype);
	switch(ftype){
		case 0x0800:
			pro += " (IPv4 - Internet Protocol version 4)";
			break;
		case 0x0806:
			pro += " (ARP - Address Resolution Protocol)";
			break;
		case 0x86dd:
			pro += " (IPv6 - Internet Protocol version 6)";
			break;
		default:
			pro += " (Unknown)";
	}

	*ret << dst << src << pro;   // add info to return list
	return ret;
}

QStringList * OpenSF::prase_ip(ip_header *ih)
{
	QStringList *ret = new QStringList();
	QString tmp;
	unsigned short tshort;

	if((ih->ver_ihl & 0xf0) == 0x40){
		*ret << "Version : 4";
	}
	tmp.sprintf("Header Length: %d Bytes", (ih->ver_ihl & 0xf) * 4);
	*ret << tmp;

	// first 6 bits are service class, the other 2 bits are ECN info
	tmp.sprintf("Differentiated Services: %02X", ih->tos);
	*ret << tmp;

	tmp.sprintf("Total Length: %d Bytes", ntohs(ih->tlen));
	*ret << tmp;

	tmp.sprintf("Identification: %02X", ntohs(ih->identification));
	*ret << tmp;

	// first 1 bit reserved, remain 2 bits are DF & MF
	tshort = (ih->flags_fo & 0xe000) >> 13;
	tmp.sprintf("Flags: %02X", tshort);
	if(tshort == 1){
		tmp += " (More Fragment)";
	}
	if(tshort == 2){
		tmp += " (Don't Fragment)";
	}
	*ret << tmp;

	// offset
	tshort = ih->flags_fo & 0x1fff;
	tmp.sprintf("Fragment Offset: %d", tshort);
	*ret << tmp;

	// ttl
	tmp.sprintf("Time to live: %d", ih->ttl);
	*ret << tmp;

	// protoco;l
	tmp.sprintf("Protocol: %02X ", ih->proto);
	switch(ih->proto){
		case 1:
			tmp += "(ICMP)";
			break;
		case 2:
			tmp += "(IGMP)";
			break;
		case 6:
			tmp += "(TCP)";
			break;
		case 17:
			tmp += "(UDP)";
			break;
	}
	*ret << tmp;

	// ip checksum
	tmp.sprintf("Header Checksum: %02X", ih->crc);
	*ret << tmp;

	// src & dst address
	tmp.sprintf("Source: %d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
	*ret << tmp;
	tmp.sprintf("Destination: %d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
	*ret << tmp;

	return ret;
}

QStringList * OpenSF::prase_tcp(tcp_header *th)
{
	QStringList *ret = new QStringList();
	QString tmp;
	char pro[10];
	unsigned short tshort;

	// src & dst port
	tshort = ntohs(th->sport);
	judge_proto(tshort, pro, "Undefine");
	tmp.sprintf("Source port: %d (%s)", tshort, pro);
	*ret << tmp;
	tshort = ntohs(th->dport);
	judge_proto(tshort, pro, "Undefine");
	tmp.sprintf("Destination port: %d (%s)", tshort, pro);
	*ret << tmp;

	// seq number & ack num
	tmp.sprintf("Sequence number: %d", ntohl(th->seqnum));
	*ret << tmp;
	tmp.sprintf("Acknowledge number: %d", ntohl(th->acknum));
	*ret << tmp;

	// tcp header length: (4 bits)
	tshort = (th->hl_flag & 0xf000) >> 12;
	tmp.sprintf("Header length: %d", tshort * 4);
	*ret << tmp;

	// flags
	tshort = th->hl_flag & 0x00ff;
	tmp.sprintf("Flags: %02X", tshort);
	*ret << tmp;

	// window size
	tmp.sprintf("Window size: %d", ntohs(th->wsize));
	*ret << tmp;

	// checksum
	tmp.sprintf("Checksum: %d", ntohs(th->crc));
	*ret << tmp;

	return ret;
}

QStringList * OpenSF::prase_udp(udp_header *uh)
{
	QStringList *ret = new QStringList();
	QString tmp;
	char pro[10];
	unsigned short tshort;

	// src & dst port
	tshort = ntohs(uh->sport);
	judge_proto(tshort, pro, "Undefine");
	tmp.sprintf("Source port: %d (%s)", tshort, pro);
	*ret << tmp;
	tshort = ntohs(uh->dport);
	judge_proto(tshort, pro, "Undefine");
	tmp.sprintf("Destination port: %d (%s)", tshort, pro);
	*ret << tmp;

	// Length & checksum
	tmp.sprintf("Length: %d", ntohs(uh->len));
	*ret << tmp;
	tmp.sprintf("Checksum: %04X", uh->crc);
	*ret << tmp;

	return ret;
}

void OpenSF::judge_proto(int port, char *str, char *def)
{
	switch(port){
		case 21:
			strcpy(str, "FTP");
			break;
		case 22:
			strcpy(str, "SSH");
			break;
		case 23:
			strcpy(str, "Telnet");
			break;
		case 25:
			strcpy(str, "SMTP");
			break;
		case 43:
			strcpy(str, "WHOIS");
			break;
		case 53:
			strcpy(str, "DNS");
			break;
		case 80:
			strcpy(str, "HTTP");
			break;
		case 115:
			strcpy(str, "SFTP");
			break;
		case 161:
			strcpy(str, "SNMP");
			break;
		default:
			strcpy(str, def);
	}
}


OpenSF::~OpenSF()
{
	pcap_freealldevs(alldevs);
	thread_mgr->quit();
	delete thread_mgr;
	delete capture;
}
