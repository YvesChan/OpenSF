#include "opensf.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	OpenSF w;
	w.show();
	return a.exec();
}
