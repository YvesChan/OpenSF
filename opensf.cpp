#include <QtGui>
#include <string>
#include <QThread>

#include "pcap.h"
#include "opensf.h"


OpenSF::OpenSF(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);
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
	ui.tableWidget->setColumnWidth(2, 150);
	ui.tableWidget->setColumnWidth(3, 150);
	ui.tableWidget->setColumnWidth(4, 60);
	ui.tableWidget->setColumnWidth(5, 60);
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

// display packet 
int OpenSF::display(int pkt_num)
{
	pkts = capture->get_pkt_list();
	while(index <= pkt_num){
		printf("%d: %s,%.6d  len:%d\n", (*pkts)[index].timestr, (*pkts)[index].ms, (*pkts)[index].len);
		index ++;
	}
	return index;
}

OpenSF::~OpenSF()
{

}
