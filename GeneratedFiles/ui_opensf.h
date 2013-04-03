/********************************************************************************
** Form generated from reading UI file 'opensf.ui'
**
** Created: Tue Apr 2 23:13:56 2013
**      by: Qt User Interface Compiler version 4.8.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_OPENSF_H
#define UI_OPENSF_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenuBar>
#include <QtGui/QPlainTextEdit>
#include <QtGui/QScrollArea>
#include <QtGui/QSplitter>
#include <QtGui/QStatusBar>
#include <QtGui/QTableWidget>
#include <QtGui/QToolBar>
#include <QtGui/QTreeWidget>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_OpenSFClass
{
public:
    QWidget *centralWidget;
    QSplitter *splitter;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QTableWidget *tableWidget;
    QScrollArea *scrollArea_2;
    QWidget *scrollAreaWidgetContents_2;
    QTreeWidget *treeWidget;
    QScrollArea *scrollArea_3;
    QWidget *scrollAreaWidgetContents_3;
    QPlainTextEdit *plainTextEdit;
    QMenuBar *menuBar;
    QStatusBar *statusBar;
    QToolBar *mainToolBar;

    void setupUi(QMainWindow *OpenSFClass)
    {
        if (OpenSFClass->objectName().isEmpty())
            OpenSFClass->setObjectName(QString::fromUtf8("OpenSFClass"));
        OpenSFClass->resize(746, 562);
        centralWidget = new QWidget(OpenSFClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        splitter = new QSplitter(centralWidget);
        splitter->setObjectName(QString::fromUtf8("splitter"));
        splitter->setGeometry(QRect(0, 0, 741, 501));
        splitter->setOrientation(Qt::Vertical);
        scrollArea = new QScrollArea(splitter);
        scrollArea->setObjectName(QString::fromUtf8("scrollArea"));
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName(QString::fromUtf8("scrollAreaWidgetContents"));
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 739, 210));
        tableWidget = new QTableWidget(scrollAreaWidgetContents);
        if (tableWidget->columnCount() < 7)
            tableWidget->setColumnCount(7);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(0, __qtablewidgetitem);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(1, __qtablewidgetitem1);
        QTableWidgetItem *__qtablewidgetitem2 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(2, __qtablewidgetitem2);
        QTableWidgetItem *__qtablewidgetitem3 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(3, __qtablewidgetitem3);
        QTableWidgetItem *__qtablewidgetitem4 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(4, __qtablewidgetitem4);
        QTableWidgetItem *__qtablewidgetitem5 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(5, __qtablewidgetitem5);
        QTableWidgetItem *__qtablewidgetitem6 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(6, __qtablewidgetitem6);
        if (tableWidget->rowCount() < 1)
            tableWidget->setRowCount(1);
        QTableWidgetItem *__qtablewidgetitem7 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(0, __qtablewidgetitem7);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setGeometry(QRect(0, 0, 741, 211));
        scrollArea->setWidget(scrollAreaWidgetContents);
        splitter->addWidget(scrollArea);
        scrollArea_2 = new QScrollArea(splitter);
        scrollArea_2->setObjectName(QString::fromUtf8("scrollArea_2"));
        scrollArea_2->setWidgetResizable(true);
        scrollAreaWidgetContents_2 = new QWidget();
        scrollAreaWidgetContents_2->setObjectName(QString::fromUtf8("scrollAreaWidgetContents_2"));
        scrollAreaWidgetContents_2->setGeometry(QRect(0, 0, 739, 161));
        treeWidget = new QTreeWidget(scrollAreaWidgetContents_2);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem(treeWidget);
        new QTreeWidgetItem(__qtreewidgetitem);
        new QTreeWidgetItem(__qtreewidgetitem);
        new QTreeWidgetItem(__qtreewidgetitem);
        new QTreeWidgetItem(__qtreewidgetitem);
        new QTreeWidgetItem(__qtreewidgetitem);
        QTreeWidgetItem *__qtreewidgetitem1 = new QTreeWidgetItem(treeWidget);
        new QTreeWidgetItem(__qtreewidgetitem1);
        new QTreeWidgetItem(__qtreewidgetitem1);
        new QTreeWidgetItem(__qtreewidgetitem1);
        QTreeWidgetItem *__qtreewidgetitem2 = new QTreeWidgetItem(treeWidget);
        new QTreeWidgetItem(__qtreewidgetitem2);
        new QTreeWidgetItem(__qtreewidgetitem2);
        new QTreeWidgetItem(treeWidget);
        treeWidget->setObjectName(QString::fromUtf8("treeWidget"));
        treeWidget->setGeometry(QRect(0, 0, 741, 161));
        scrollArea_2->setWidget(scrollAreaWidgetContents_2);
        splitter->addWidget(scrollArea_2);
        scrollArea_3 = new QScrollArea(splitter);
        scrollArea_3->setObjectName(QString::fromUtf8("scrollArea_3"));
        scrollArea_3->setWidgetResizable(true);
        scrollAreaWidgetContents_3 = new QWidget();
        scrollAreaWidgetContents_3->setObjectName(QString::fromUtf8("scrollAreaWidgetContents_3"));
        scrollAreaWidgetContents_3->setGeometry(QRect(0, 0, 739, 114));
        plainTextEdit = new QPlainTextEdit(scrollAreaWidgetContents_3);
        plainTextEdit->setObjectName(QString::fromUtf8("plainTextEdit"));
        plainTextEdit->setGeometry(QRect(0, 0, 531, 111));
        scrollArea_3->setWidget(scrollAreaWidgetContents_3);
        splitter->addWidget(scrollArea_3);
        OpenSFClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(OpenSFClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 746, 23));
        OpenSFClass->setMenuBar(menuBar);
        statusBar = new QStatusBar(OpenSFClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        OpenSFClass->setStatusBar(statusBar);
        mainToolBar = new QToolBar(OpenSFClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        OpenSFClass->addToolBar(Qt::TopToolBarArea, mainToolBar);

        retranslateUi(OpenSFClass);

        QMetaObject::connectSlotsByName(OpenSFClass);
    } // setupUi

    void retranslateUi(QMainWindow *OpenSFClass)
    {
        OpenSFClass->setWindowTitle(QApplication::translate("OpenSFClass", "OpenSF", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem = tableWidget->horizontalHeaderItem(0);
        ___qtablewidgetitem->setText(QApplication::translate("OpenSFClass", "No.", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem1 = tableWidget->horizontalHeaderItem(1);
        ___qtablewidgetitem1->setText(QApplication::translate("OpenSFClass", "Time", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem2 = tableWidget->horizontalHeaderItem(2);
        ___qtablewidgetitem2->setText(QApplication::translate("OpenSFClass", "Source", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem3 = tableWidget->horizontalHeaderItem(3);
        ___qtablewidgetitem3->setText(QApplication::translate("OpenSFClass", "Destination", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem4 = tableWidget->horizontalHeaderItem(4);
        ___qtablewidgetitem4->setText(QApplication::translate("OpenSFClass", "Protocol", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem5 = tableWidget->horizontalHeaderItem(5);
        ___qtablewidgetitem5->setText(QApplication::translate("OpenSFClass", "Length", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem6 = tableWidget->horizontalHeaderItem(6);
        ___qtablewidgetitem6->setText(QApplication::translate("OpenSFClass", "Info", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem7 = tableWidget->verticalHeaderItem(0);
        ___qtablewidgetitem7->setText(QApplication::translate("OpenSFClass", "1", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem = treeWidget->headerItem();
        ___qtreewidgetitem->setText(1, QApplication::translate("OpenSFClass", "Value", 0, QApplication::UnicodeUTF8));
        ___qtreewidgetitem->setText(0, QApplication::translate("OpenSFClass", "Key", 0, QApplication::UnicodeUTF8));

        const bool __sortingEnabled = treeWidget->isSortingEnabled();
        treeWidget->setSortingEnabled(false);
        QTreeWidgetItem *___qtreewidgetitem1 = treeWidget->topLevelItem(0);
        ___qtreewidgetitem1->setText(0, QApplication::translate("OpenSFClass", "Frame", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem2 = ___qtreewidgetitem1->child(0);
        ___qtreewidgetitem2->setText(0, QApplication::translate("OpenSFClass", "Arrive time", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem3 = ___qtreewidgetitem1->child(1);
        ___qtreewidgetitem3->setText(0, QApplication::translate("OpenSFClass", "Frame Number", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem4 = ___qtreewidgetitem1->child(2);
        ___qtreewidgetitem4->setText(0, QApplication::translate("OpenSFClass", "Frame Length", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem5 = ___qtreewidgetitem1->child(3);
        ___qtreewidgetitem5->setText(0, QApplication::translate("OpenSFClass", "Capture Length", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem6 = ___qtreewidgetitem1->child(4);
        ___qtreewidgetitem6->setText(0, QApplication::translate("OpenSFClass", "Protocol in frame", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem7 = treeWidget->topLevelItem(1);
        ___qtreewidgetitem7->setText(0, QApplication::translate("OpenSFClass", "Ethernet", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem8 = ___qtreewidgetitem7->child(0);
        ___qtreewidgetitem8->setText(0, QApplication::translate("OpenSFClass", "Destination", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem9 = ___qtreewidgetitem7->child(1);
        ___qtreewidgetitem9->setText(0, QApplication::translate("OpenSFClass", "Source", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem10 = ___qtreewidgetitem7->child(2);
        ___qtreewidgetitem10->setText(0, QApplication::translate("OpenSFClass", "Type", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem11 = treeWidget->topLevelItem(2);
        ___qtreewidgetitem11->setText(0, QApplication::translate("OpenSFClass", "IP", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem12 = ___qtreewidgetitem11->child(0);
        ___qtreewidgetitem12->setText(0, QApplication::translate("OpenSFClass", "Version", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem13 = ___qtreewidgetitem11->child(1);
        ___qtreewidgetitem13->setText(0, QApplication::translate("OpenSFClass", "Header Length", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem14 = treeWidget->topLevelItem(3);
        ___qtreewidgetitem14->setText(0, QApplication::translate("OpenSFClass", "TCP", 0, QApplication::UnicodeUTF8));
        treeWidget->setSortingEnabled(__sortingEnabled);

    } // retranslateUi

};

namespace Ui {
    class OpenSFClass: public Ui_OpenSFClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_OPENSF_H
