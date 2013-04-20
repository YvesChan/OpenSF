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

// display packet. 
void OpenSF::display(int pkt_num)
{
	QString time_stamp;
	QString src;
	QString dst;
	QString pro;
	mac_header *mh;
	ip_header *ih;
	unsigned int ip_len;
	tcp_header *th;
	udp_header *uh;
	unsigned short sport, dport;    // source, distination port

	index = (vector<pkt_info>::size_type)pkt_num;
	time_stamp.sprintf("%s,%.6d", (*pkts)[index].timestr, (*pkts)[index].ms);
	
	// get mac header position
	mh = (mac_header *)(*pkts)[index].pkt_data;
	u_short ftype = ntohs(mh->type);     // frame type, since it's two bytes, it needs to be transformed

	/* printf("  dst:%02X-%02X-%02X-%02X-%02X-%02X src:%02X-%02X-%02X-%02X-%02X-%02X   ", 
		mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5],
		mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
	// printf("frame type: %x\n", ftype);
	// cout << endl;  */

	switch(ftype){     // EtherType, see more:http://en.wikipedia.org/wiki/Ethertype
		case 0x0806:     // ARP packet
			src.sprintf("%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			dst.sprintf("%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			pro = "ARP";
			break;
		case 0x0800:     // IPv4 packet
			ih = (ip_header *)((u_char*)mh + 14);   // get ip header position
			ip_len = (ih->ver_ihl & 0xf) * 4;      // get ip header's length

			if((ih->proto ^ 0x06) == 0){      // TCP
				th = (tcp_header *)((unsigned char *)ih + ip_len);   // get TCP header position
				sport = ntohs(th->sport);
				dport = ntohs(th->dport);
				if(dport < 1024){
					judge_proto(dport, &pro, "TCP");
				}
				else {
					judge_proto(sport, &pro, "TCP");
				}
			}
			else if((ih->proto ^ 0x11) == 0){     // UDP
				uh = (udp_header *)((unsigned char *)ih + ip_len);
				sport = ntohs(uh->sport);
				dport = ntohs(uh->dport);
				if(dport < 1024){
					judge_proto(dport, &pro, "UDP");
				}
				else {
					judge_proto(sport, &pro, "UDP");
				}
			}
			else if((ih->proto ^ 0x01) == 0){
				pro = "ICMP";
			}
			else if((ih->proto ^ 0x02) == 0){
				pro = "IGMP";
			}
			else pro = "Unknown";
			
			cout << flush;
			src.sprintf("%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
			dst.sprintf("%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			// printf("      src:%d.%d.%d.%d ", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
			// printf("dst:%d.%d.%d.%d \n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
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
	
	return;
}

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
	if(ntohs(mh->type) == 0x0806){
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
		// TO DO
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
	unsigned short tshort;

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

	// tcp header length: (4 bits)
	tshort = (th->hl_flag & 0xf000) >> 12;
	tmp.sprintf("Header length: %d Bytes", tshort * 4);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

	// flags
	tshort = th->hl_flag & 0x00ff;
	tmp.sprintf("Flags: 0x%02X", tshort);
	ret->addChild(new QTreeWidgetItem(ret, QStringList(tmp)));

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

	ret->setText(0, "Address Resolution Protocol" + opcode);
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
