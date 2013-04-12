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

	// resize tablewidget's rows to fit their content
	// ui.tableWidget->resizeRowsToContents();
	ui.tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

	index = 0;    // pkt_num index initial 

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
	ui.tableWidget->setColumnWidth(2, 150);
	ui.tableWidget->setColumnWidth(3, 150);
	ui.tableWidget->setColumnWidth(4, 60);
	ui.tableWidget->setColumnWidth(5, 40);
	ui.tableWidget->setColumnWidth(6, 300);

	connect(act_start, SIGNAL(triggered()), this, SLOT(start_cap()));
	connect(act_stop, SIGNAL(triggered()), this, SLOT(stop_cap()));

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
	int dev_num = combo_box_devs->currentIndex();
	if(dev_num == 0){
		QMessageBox::information(this, "OpenSF", "Please select a network interface");
		return;
	}

	capture = new cap_thread(alldevs, dev_num);
	capture->set_status(true);
	pkts = capture->get_pkt_list();     // get pkt_list address
	QThread *thread_mgr = new QThread(this);

	QObject::connect(thread_mgr, SIGNAL(started()), capture, SLOT(pkt_cap()));
	QObject::connect(capture, SIGNAL(cap(int)), this, SLOT(display(int)));
	// connect(thread_mgr, SIGNAL(finished()), capture, SLOT(deleteLater()));
	capture->moveToThread(thread_mgr);

	// Starts an event loop, and emits workerThread->started()
	thread_mgr->start();
	
}

void OpenSF::stop_cap()
{
	capture->set_status(false);
}

// display packet. 
// return the packet amount that had been displayed so far
int OpenSF::display(int pkt_num)
{
	char time_stamp[30];
	char src[20];
	char dst[20];
	char pro[10];

	index = (vector<pkt_info>::size_type)pkt_num;
	// printf("  ->%d :", pkt_num);
	// printf("%s,%.6d  len:%d\n", (*pkts)[index].timestr, (*pkts)[index].ms, (*pkts)[index].len);
	sprintf(time_stamp, "%s,%.6d", (*pkts)[index].timestr, (*pkts)[index].ms);
	
	// get mac & ip header position
	mac_header *mh = (mac_header *)(*pkts)[index].pkt_data;
	ip_header *ih = (ip_header *)((u_char*)mh + 14);
	u_short ftype = ntohs(mh->type);     // frame type, since it's two bytes, it needs to be transformed

	printf("  dst:%02X-%02X-%02X-%02X-%02X-%02X src:%02X-%02X-%02X-%02X-%02X-%02X   ", 
		mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5],
		mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
	printf("frame type: %x\n", ftype);

	switch(ftype){     // EtherType, see more:http://en.wikipedia.org/wiki/Ethertype
		case 0x0806:     // ARP packet
			sprintf(src, "%02X-%02X-%02X-%02X-%02X-%02X", 
				mh->src[0], mh->src[1], mh->src[2], mh->src[3], mh->src[4], mh->src[5]);
			sprintf(dst, "%02X-%02X-%02X-%02X-%02X-%02X",
				mh->dst[0], mh->dst[1], mh->dst[2], mh->dst[3], mh->dst[4], mh->dst[5]);
			strcpy(pro, "ARP");
			break;
		case 0x0800:     // IPv4 packet
			printf("type:%d ", ih->proto);
			if((ih->proto ^ 0x06) == 0){
				strcpy(pro, "TCP");
			}
			else if((ih->proto ^ 0x11) == 0){
				strcpy(pro, "UDP");
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
		case 0x86DD:
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
	
	return pkt_num;
}


OpenSF::~OpenSF()
{

}
