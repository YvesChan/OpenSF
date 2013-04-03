#include "opensf.h"
#include "pcap.h"
#include "lib.h"
#include <QtGui>

OpenSF::OpenSF(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	QComboBox *combo_box = new QComboBox(this);
	QActionGroup *act_grp = new QActionGroup(this);
	QAction *act_start = new QAction("Start", act_grp);
	QAction *act_stop = new QAction("Stop", act_grp);
	act_grp->addAction(act_start);
	act_grp->addAction(act_stop);
	act_stop->setEnabled(false);
	act_grp->setExclusive(true);

	dev_list *dlist = find_devs();
	while(dlist){
		combo_box->addItem(dlist->name);
		dlist = dlist->next;
	}

	ui.mainToolBar->addWidget(combo_box);
	ui.mainToolBar->addAction(act_start);
	ui.mainToolBar->addAction(act_stop);


	// readSettings();

	//QScrollArea *pkt_list = new QScrollArea();
	//QScrollArea *pkt_osi = new QScrollArea();
	//QScrollArea *pkt_data = new QScrollArea();

	//QSplitter *splitter = new QSplitter(Qt::Vertical);
	//splitter->addWidget(pkt_list);
	//splitter->addWidget(pkt_osi);
	//splitter->addWidget(pkt_data);

	//this->setCentralWidget(splitter);
}

OpenSF::~OpenSF()
{

}
