#ifndef OPENSF_H
#define OPENSF_H

#include <QtGui/QMainWindow>
#include "ui_opensf.h"

class OpenSF : public QMainWindow
{
	Q_OBJECT

public:
	OpenSF(QWidget *parent = 0, Qt::WFlags flags = 0);
	~OpenSF();

private:
	Ui::OpenSFClass ui;
};

#endif // OPENSF_H
