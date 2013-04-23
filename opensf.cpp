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
	act_start = new QAction(QIcon("Resources\\start.png"), "Start", act_grp);
	act_stop = new QAction(QIcon("Resources\\stop.png"), "Stop", act_grp);
	act_apply = new QAction(QIcon("Resources\\apply.png"), "Apply", this);
	act_clear = new QAction(QIcon("Resources\\clear.png"), "Clear", this);

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

	ui.mainToolBar->addWidget(new QLabel("Filter:", this));
	ui.mainToolBar->addWidget(combo_box_filter);
	ui.mainToolBar->addAction(act_apply);
	ui.mainToolBar->addAction(act_clear);

	combo_box_devs->resize(200, 40);
	combo_box_filter->resize(300, 40);

	// configure tablewidget style
	ui.tableWidget->verticalHeader()->setVisible(false);     // Disable the row header
	ui.tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);    // select the whole row
	ui.tableWidget->setColumnWidth(0, 40);
	ui.tableWidget->setColumnWidth(1, 120);
	ui.tableWidget->setColumnWidth(2, 140);
	ui.tableWidget->setColumnWidth(3, 140);
	ui.tableWidget->setColumnWidth(4, 60);
	ui.tableWidget->setColumnWidth(5, 55);
	ui.tableWidget->setColumnWidth(6, 400);

	connect(act_start, SIGNAL(triggered()), this, SLOT(start_cap()));
	connect(act_stop, SIGNAL(triggered()), this, SLOT(stop_cap()));
	connect(ui.tableWidget, SIGNAL(cellClicked(int, int)), this, SLOT(show_pkt(int)));
	connect(combo_box_filter, SIGNAL(editTextChanged(const QString &)), this, SLOT(check_filter()));
	connect(act_apply, SIGNAL(triggered()), this, SLOT(apply_filter()));
	connect(act_clear, SIGNAL(triggered()), this, SLOT(clear_filter()));


	thread_mgr = new QThread(this);
	index = 0;    // pkt_num index initial 
}

void OpenSF::check_filter()
{
	// TODO: check syntax
	act_apply->setEnabled(true);
}

void OpenSF::apply_filter()
{
	if(combo_box_filter->currentText().size() >= 100){
		QMessageBox::information(this, "OpenSF", "Filter string too long(at most 100 characters)");
		return;
	}

	filter = combo_box_filter->currentText();
	combo_box_filter->clearFocus();
	act_apply->setDisabled(true);
	act_clear->setEnabled(true);
}

void OpenSF::clear_filter()
{
	filter.clear();
	combo_box_filter->clearEditText();
	act_clear->setDisabled(true);
}

// find devices and display
int OpenSF::find_devs()
{
	int fir = 0, las = 0;
	int count = 0;         // amount of devices
	char errbuf[PCAP_ERRBUF_SIZE];

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
			ui.treeWidget->clear();
			capture->deleteLater();    // delete old capture instance, especially for *pkts
		}
		else {
			act_stop->setChecked(true);
			return;
		}
	}

	// start a capture
	int dev_num = combo_box_devs->currentIndex();
	if(dev_num == 0){
		QMessageBox::information(this, "OpenSF", "Please select a network interface");
		return;
	}

	capture = new cap_thread(alldevs, dev_num);
	capture->set_status(true);
	capture->set_filter(filter.toLatin1().data());
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

// display packet's basic infomations in tablewidget as list
void OpenSF::display(int pkt_num)
{
	QString time_stamp;
	QString src;
	QString dst;
	QString pro;
	QString info;
	mac_header *mh;
	ip_header *ih;
	unsigned int ip_len;
	tcp_header *th;
	udp_header *uh;
	unsigned short sport, dport;    // source, distination port
	arp_payload *ap;
	icmp_payload *ic;
	dns_payload *dp;

	index = (vector<pkt_info>::size_type)pkt_num;
	time_stamp.sprintf("%s,%.6d", (*pkts)[index].timestr, (*pkts)[index].ms);
	
	// get mac header position
	mh = (mac_header *)(*pkts)[index].pkt_data;
	u_short ftype = ntohs(mh->type);     // frame type, since it's two bytes, it needs to be transformed

	switch(ftype){     // EtherType, see more:http://en.wikipedia.org/wiki/Ethertype
		case 0x0806:     // ARP packet
			src.sprintf("%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			dst.sprintf("%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			pro = "ARP";
			ap = (arp_payload *)((u_char *)mh + 14);
			if(ntohs(ap->op) == 1){
				info.sprintf("Who has %d.%d.%d.%d?  Tell %d.%d.%d.%d", 
					ap->ipdst.byte1, ap->ipdst.byte2, ap->ipdst.byte3, ap->ipdst.byte4, 
					ap->ipsrc.byte1, ap->ipsrc.byte2, ap->ipsrc.byte3, ap->ipsrc.byte4);
			}
			else {
				info.sprintf("%d.%d.%d.%d is at %02X-%02X-%02X-%02X-%02X-%02X",
					ap->ipsrc.byte1, ap->ipsrc.byte2, ap->ipsrc.byte3, ap->ipsrc.byte4,
					ap->src[0], ap->src[1], ap->src[2], ap->src[3], ap->src[4], ap->src[5]);
			}
			break;
		case 0x0800:     // IPv4 packet
			ih = (ip_header *)((u_char*)mh + 14);   // get ip header position
			ip_len = (ih->ver_ihl & 0xf) * 4;      // get ip header's length

			switch(ih->proto){
				case 6:          // TCP
					th = (tcp_header *)((unsigned char *)ih + ip_len);   // get TCP header position
					sport = ntohs(th->sport);
					dport = ntohs(th->dport);
					if(dport < 1024){
						judge_proto(dport, &pro, "TCP");
					}
					else {
						judge_proto(sport, &pro, "TCP");
					}
					break;
				case 17:		// UDP
					uh = (udp_header *)((unsigned char *)ih + ip_len);
					sport = ntohs(uh->sport);
					dport = ntohs(uh->dport);
					if(dport < 1024){
						judge_proto(dport, &pro, "UDP");
					}
					else {
						judge_proto(sport, &pro, "UDP");
					}
					if(pro.compare("DNS") == 0){
						dp = (dns_payload *)((u_char *)uh + 8);
						if((dp->flags & 0x8000) == 0x8000)
							info.sprintf("Standard Query Response");
						else 
							info.sprintf("Standard Query");
					}
					break;
				case 1:
					pro = "ICMP";
					ic = (icmp_payload *)((unsigned char *)ih + ip_len);
					switch(ic->type){
						case 0:
							info = "Echo(ping) reply";
							break;
						case 3:
							info = "Target unreachable";
							break;
						case 8:
							info = "Echo(ping) request";
							break;
						case 11:
							info = "Time out";
							break;
					}
					break;		
				case 2:
					pro = "IGMP";
					break;
				default:
					pro = "Unknown";
			}

			// cout << flush;
			src.sprintf("%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
			dst.sprintf("%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			break;
		case 0x86DD:       // IPv6
			// TO DO
			src.sprintf("%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			dst.sprintf("%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			pro = "IPv6";
			break;
		default:
			src.sprintf("%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			dst.sprintf("%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			pro = "Unknown";
	}

	// add table data
	ui.tableWidget->insertRow(pkt_num);
	ui.tableWidget->setItem(pkt_num, 0, new QTableWidgetItem(QString::number(pkt_num)));
	ui.tableWidget->setItem(pkt_num, 1, new QTableWidgetItem(time_stamp));
	ui.tableWidget->setItem(pkt_num, 2, new QTableWidgetItem(src));
	ui.tableWidget->setItem(pkt_num, 3, new QTableWidgetItem(dst));
	ui.tableWidget->setItem(pkt_num, 4, new QTableWidgetItem(pro));
	ui.tableWidget->setItem(pkt_num, 5, new QTableWidgetItem(QString::number((*pkts)[index].len)));
	ui.tableWidget->setItem(pkt_num, 6, new QTableWidgetItem(info));
	
	return;
}

// show packet's details in treewidget
void OpenSF::show_pkt(int row)
{
	// clear treewidget
	if(ui.treeWidget->topLevelItemCount() != 0){
		ui.treeWidget->clear();
	}

	index = (vector<pkt_info>::size_type)row;
	QTreeWidgetItem *dll;		// data link layer
	QTreeWidgetItem *nl;		// network layer
	QTreeWidgetItem *tl;		// transport layer
	QTreeWidgetItem *payload;	// datagram payload

	// show mac header and apr info(if exist)
	mac_header *mh = (mac_header *)(*pkts)[index].pkt_data;
	dll = prase_mac(mh);
	ui.treeWidget->insertTopLevelItem(0, dll);
	if(ntohs(mh->type) == 0x0806){       // ARP
		arp_payload *ap = (arp_payload *)((u_char *)mh + 14);
		payload = prase_arp(ap);
		ui.treeWidget->insertTopLevelItem(1, payload);
		return;
	}

	// show ip header info
	ip_header *ih = (ip_header *)((u_char*)mh + 14);
	nl = prase_ip(ih);
	ui.treeWidget->insertTopLevelItem(1, nl);
	if(ih->proto == 1 || ih->proto == 2){    // ICMP & IGMP 
		icmp_payload *ic = (icmp_payload *)((u_char *)ih + (ih->ver_ihl & 0xf) * 4);
		payload = prase_icmp(ic);
		ui.treeWidget->insertTopLevelItem(2, payload);
		return;
	}

	// get tcp/udp header 
	if(ih->proto == 6){     // TCP
		tcp_header *th = (tcp_header *)((unsigned char *)ih + (ih->ver_ihl & 0xf) * 4);
		tl = prase_tcp(th);
		ui.treeWidget->insertTopLevelItem(2, tl);
	}
	else if(ih->proto == 17){    // UDP
		udp_header *uh = (udp_header *)((unsigned char *)ih + (ih->ver_ihl & 0xf) * 4);
		tl = prase_udp(uh);
		ui.treeWidget->insertTopLevelItem(2, tl);

		// tmp implement
		if(ntohs(uh->dport) == 53 || ntohs(uh->sport) == 53){
			dns_payload *dp = (dns_payload *)((u_char *)uh + 8);
			payload = prase_dns(dp);
			ui.treeWidget->insertTopLevelItem(3, payload);
		}
	}

}

QTreeWidgetItem * OpenSF::prase_mac(mac_header *mh)
{
	QTreeWidgetItem *ret = new QTreeWidgetItem(ui.treeWidget);
	u_short ftype = ntohs(mh->type);
	QString src;
	QString dst;
	QString pro;

	src.sprintf("%02X-%02X-%02X-%02X-%02X-%02X", mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
	dst.sprintf("%02X-%02X-%02X-%02X-%02X-%02X", mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
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

	// add info to return list
	ret->setText(0, "Data Link Layer  --  Src: " + src + ", Dst: " + dst);
	ret->addChild(new QTreeWidgetItem(ret, QStringList("Destination: " + dst)));
	ret->addChild(new QTreeWidgetItem(ret, QStringList("Source: " + src)));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(pro)));
	return ret;
}

QTreeWidgetItem * OpenSF::prase_ip(ip_header *ih)
{
	QTreeWidgetItem *ret = new QTreeWidgetItem(ui.treeWidget);
	QString src;
	QString dst;
	QString tmp;
	unsigned short tshort;

	// ip version & header length
	if((ih->ver_ihl & 0xf0) == 0x40){
		ret->addChild(new QTreeWidgetItem(ret, QStringList(QString("Version : 4"))));
	}
	tmp.sprintf("Header Length: %d Bytes", (ih->ver_ihl & 0xf) * 4);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// first 6 bits are service class, the other 2 bits are ECN info
	tmp.sprintf("Differentiated Services: %02X", ih->tos);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	tmp.sprintf("Total Length: %d Bytes", ntohs(ih->tlen));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	tmp.sprintf("Identification: %02X", ntohs(ih->identification));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// first 1 bit reserved, remain 2 bits are DF & MF
	tshort = (ih->flags_fo & 0xe000) >> 13;
	tmp.sprintf("Flags: 0x%02X", tshort);
	if(tshort == 1){
		tmp += " (More Fragment)";
	}
	if(tshort == 2){
		tmp += " (Don't Fragment)";
	}
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// offset
	tshort = ih->flags_fo & 0x1fff;
	tmp.sprintf("Fragment Offset: %d", tshort);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// ttl
	tmp.sprintf("Time to live: %u", ih->ttl);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// protoco;l
	tmp.sprintf("Protocol: 0x%02X ", ih->proto);
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
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// ip checksum
	tmp.sprintf("Header Checksum: 0x%02X", ih->crc);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// src & dst address
	src.sprintf("%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
	ret->addChild(new QTreeWidgetItem(ret, QStringList("Source: " + src)));
	dst.sprintf("%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
	ret->addChild(new QTreeWidgetItem(ret, QStringList("Destination: " + dst)));

	ret->setText(0, "Network Layer  --  Src: " + src + ", Dst: " + dst);
	return ret;
}

QTreeWidgetItem * OpenSF::prase_tcp(tcp_header *th)
{
	QTreeWidgetItem *ret = new QTreeWidgetItem(ui.treeWidget);
	QString tmp;
	QString pro;
	QString fstr;
	unsigned short tshort;
	unsigned char tchar;

	// src & dst port
	tshort = ntohs(th->sport);
	judge_proto(tshort, &pro, "Undefine");
	tmp.sprintf("Source port: %d ", tshort);
	tmp += "(" + pro + ")";
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tshort = ntohs(th->dport);
	judge_proto(tshort, &pro, "Undefine");
	tmp.sprintf("Destination port: %d ", tshort);
	tmp += "(" + pro + ")";
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// seq number & ack num
	tmp.sprintf("Sequence number: %u", ntohl(th->seqnum));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Acknowledge number: %u", ntohl(th->acknum));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// tcp header length: (4 bits): NOTE here to change byte order
	tshort = (ntohs(th->hl_flag) & 0xf000) >> 12;
	tmp.sprintf("Header length: %d Bytes", tshort * 4);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// flags
	tshort = ntohs(th->hl_flag) & 0x00ff;
	fstr.sprintf("Flags: 0x%04X (", tshort);
	tchar = (u_char)tshort;
	QTreeWidgetItem * flags = new QTreeWidgetItem(ret);

	if((tchar & 0x80) == 0x80){		// CWR
		tmp = "1... .... = Congestion Window Reduced (CWR): Set";
		fstr += " CWR";
	}
	else 
		tmp = "0... .... = Congestion Window Reduced (CWR): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));

	if((tchar & 0x40) == 0x40){		// ECE
		tmp = ".1.. .... = ECN-Echo(ECE): Set";
		fstr += " ECE";
	}
	else 
		tmp = ".0.. .... = ECN-Echo(ECE): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));

	if((tchar & 0x20) == 0x20){		// URG
		tmp = "..1. .... = Urgent Pointer (URG): Set";
		fstr += " URG";
	}
	else 
		tmp = "..0. .... = Urgent Pointer (URG): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));

	if((tchar & 0x10) == 0x10){		// ACK
		tmp = "...1 .... = Acknowledge (ACK): Set";
		fstr += " ACK";
	}
	else 
		tmp = "...0 .... = Urgent Pointer (ACK): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));

	if((tchar & 0x08) == 0x08){		// PSH
		tmp = ".... 1... = Push (PSH): Set";
		fstr += " PSH";
	}
	else 
		tmp = ".... 0... = Push (PSH): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));

	if((tchar & 0x04) == 0x04){		// RST
		tmp = ".... .1.. = Reset (RST): Set";
		fstr += " RST";
	}
	else 
		tmp = ".... .0.. = Reset (PSH): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));

	if((tchar & 0x02) == 0x02){		// SYN
		tmp = ".... ..1. = Sync (SYN): Set";
		fstr += " SYN";
	}
	else 
		tmp = ".... ..0. = Sync (SYN): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));

	if((tchar & 0x01) == 0x01){		// FIN
		tmp = ".... ...1 = Finish (FIN): Set";
		fstr += " FIN";
	}
	else 
		tmp = ".... ...0 = Finish (FIN): Not Set";
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));
	
	fstr += " )";
	flags->setText(0, fstr);
	// flags complete

	// window size
	tmp.sprintf("Window size: %d", ntohs(th->wsize));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// checksum
	tmp.sprintf("Checksum: 0x%d", ntohs(th->crc));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	ret->setText(0, "Transport Layer  --  TCP");
	return ret;
}

QTreeWidgetItem * OpenSF::prase_udp(udp_header *uh)
{
	QTreeWidgetItem *ret = new QTreeWidgetItem(ui.treeWidget);
	QString tmp;
	QString pro;
	unsigned short tshort;

	// src & dst port
	tshort = ntohs(uh->sport);
	judge_proto(tshort, &pro, "Undefine");
	tmp.sprintf("Source port: %d ", tshort);
	tmp += "(" + pro + ")";
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tshort = ntohs(uh->dport);
	judge_proto(tshort, &pro, "Undefine");
	tmp.sprintf("Destination port: %d ", tshort);
	tmp += "(" + pro + ")";
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// Length & checksum
	tmp.sprintf("Length: %d", ntohs(uh->len));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Checksum: 0x%04X", uh->crc);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	ret->setText(0, "Transport Layer  --  UDP");
	return ret;
}

QTreeWidgetItem * OpenSF::prase_arp(arp_payload *ap)
{
	QTreeWidgetItem *ret = new QTreeWidgetItem(ui.treeWidget);
	QString opcode;
	QString tmp;
	
	// hardware type & protocol type (2 + 2)Bytes
	tmp.sprintf("Hardware type: %d", ntohs(ap->hardware));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Protocol type: %d", ntohs(ap->proto));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// Length of hardware address(6) & protocol address(4) in Byte
	tmp.sprintf("Hardware address length: %d", ap->haddr_len);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Protocol address length: %d", ap->paddr_len);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// op code
	switch(ntohs(ap->op)){
		case 1:
			opcode.sprintf("request(1)");
			break;
		case 2:
			opcode.sprintf("reply(2)");
			break;
		default:
			opcode.sprintf("RARP");
	}
	ret->addChild(new QTreeWidgetItem(ret, QStringList("Opcode: " + opcode)));

	// addresses
	tmp.sprintf("Sender MAC address: %02X-%02X-%02X-%02X-%02X-%02X", ap->src[0], ap->src[1], ap->src[2], ap->src[3], ap->src[4], ap->src[5]);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Sender IP address: %d.%d.%d.%d", ap->ipsrc.byte1, ap->ipsrc.byte2, ap->ipsrc.byte3, ap->ipsrc.byte4);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Target MAC address: %02X-%02X-%02X-%02X-%02X-%02X", ap->dst[0], ap->dst[1], ap->dst[2], ap->dst[3], ap->dst[4], ap->dst[5]);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Target IP address: %d.%d.%d.%d", ap->ipdst.byte1, ap->ipdst.byte2, ap->ipdst.byte3, ap->ipdst.byte4);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	ret->setText(0, "Address Resolution Protocol  (" + opcode + ")");
	return ret;
}

QTreeWidgetItem * OpenSF::prase_icmp(icmp_payload *ic)
{
	QTreeWidgetItem *ret = new QTreeWidgetItem(ui.treeWidget);
	QString tmp;

	tmp.sprintf("Type: %d", ic->type);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Code: %d", ic->code);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Checksum: %d", ntohs(ic->checksum));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Identifier: %d", ntohs(ic->id));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Sequence number: %d", ntohs(ic->seq));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	ret->setText(0, "Internet Control Message Protocol");
	return ret;
}

QTreeWidgetItem * OpenSF::prase_dns(dns_payload *dp)
{
	QTreeWidgetItem * ret = new QTreeWidgetItem(ui.treeWidget);
	QString tmp;
	u_short tshort;
	u_short f = ntohs(dp->flags);      // NOTE:   change BE to LE !!!

	tmp.sprintf("Transaction ID: %d", dp->id);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Flags: 0x%04X", f);
	QTreeWidgetItem * flags = new QTreeWidgetItem(ret, QStringList(tmp));
	tshort = (f & 0x8000) >> 15;      // QR
	if(tshort){
		tmp.sprintf("QR:%d  (Message response)", tshort);
	}
	else {
		tmp.sprintf("QR:%d  (Message query)", tshort);
	}
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));
	tshort = (f & 0x7800) >> 11;    // opcode
	switch(tshort){
		case 0:
			flags->addChild(new QTreeWidgetItem(flags, QStringList("Standard query")));
			break;
		case 1:
			flags->addChild(new QTreeWidgetItem(flags, QStringList("Reverse query")));
			break;
		default:
			flags->addChild(new QTreeWidgetItem(flags, QStringList("Server status query")));
	}
	tshort = (f & 0x0780) >> 7;     // AA(Authoritative Answer) TC(TrunCation) RD(Recursion Desired) RA(Recursion Available)
	tmp.sprintf("AA:TC:RD:RA  -  %d", tshort);
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));
	tshort = f & 0x000f;       // rcode
	tmp.sprintf("Reply code: %d  ", tshort);
	switch(tshort){
		case 0: 
			tmp += "OK";
			break;
		case 1:
			tmp += "Format error";
			break;
		case 2:
			tmp += "Server failure";
			break;
		case 3:
			tmp += "Name Error, no such name";
			break;
		default:
			tmp += "Refused";
	}
	flags->addChild(new QTreeWidgetItem(flags, QStringList(tmp)));
	ret->addChild(flags);

	tmp.sprintf("Questions: %d", ntohs(dp->ques));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Answer RRs: %d", ntohs(dp->ans));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Authority RRs: %d", ntohs(dp->aut));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Additions RRs: %d", ntohs(dp->aut));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// question segment
	QString name((char *)dp + 12);
	name[0] = 32;         // 'space'
	for(int i = 1; i < name.length(); i ++){
		if(name[i] < 32)       // invisible characters
			name[i] = '.';
	}
	ret->addChild(new QTreeWidgetItem(ret, QStringList(name)));     // query domain name
	// get query type's offset and use an unsigned short pointer!
	int offset = 12 + name.length() + 1;
	u_short *type = (u_short *)((u_char *)dp + offset);
	offset += 2;
	u_short *cla = (u_short *)((u_char *)dp + offset);
	tshort = ntohs(*type);
	tmp.sprintf("Type: 0x%02X  -  ", tshort);
	switch(tshort){
		case 1:
			tmp += "A (IP address)";
			break;
		case 2:
			tmp += "NS (name server)";
			break;
		case 5:
			tmp += "CNAME (canonical name)";
			break;
		case 15:
			tmp += "MX (mail exchange)";
	}
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));
	tmp.sprintf("Class: 0x%02X", ntohs(*cla));
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// TO DO : Answer Segment

	ret->setText(0, "Domain Name System");
	return ret;
}



void OpenSF::judge_proto(int port, QString *str, QString def)
{
	switch(port){
		case 21:
			*str = "FTP";
			break;
		case 22:
			*str = "SSH";
			break;
		case 23:
			*str = "Telnet";
			break;
		case 25:
			*str = "SMTP";
			break;
		case 43:
			*str = "WHOIS";
			break;
		case 53:
			*str = "DNS";
			break;
		case 80:
			*str = "HTTP";
			break;
		case 115:
			*str = "SFTP";
			break;
		case 161:
			*str = "SNMP";
			break;
		case 443:
			*str = "SSL";
			break;
		case 1900:
			*str = "SSDP";
			break;
		default:
			*str = def;
	}
}


OpenSF::~OpenSF()
{
	pcap_freealldevs(alldevs);
	thread_mgr->quit();
	delete thread_mgr;
	delete capture;
}
