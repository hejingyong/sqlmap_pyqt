# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main_window.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(791, 602)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 791, 561))
        self.tabWidget.setObjectName("tabWidget")
        self.tab_1 = QtWidgets.QWidget()
        self.tab_1.setObjectName("tab_1")
        self.pushButton_analyse = QtWidgets.QPushButton(self.tab_1)
        self.pushButton_analyse.setGeometry(QtCore.QRect(260, 20, 91, 31))
        self.pushButton_analyse.setObjectName("pushButton_analyse")
        self.lineEdit_analyse_url = QtWidgets.QLineEdit(self.tab_1)
        self.lineEdit_analyse_url.setGeometry(QtCore.QRect(50, 20, 211, 31))
        self.lineEdit_analyse_url.setObjectName("lineEdit_analyse_url")
        self.label_url = QtWidgets.QLabel(self.tab_1)
        self.label_url.setGeometry(QtCore.QRect(10, 30, 31, 16))
        self.label_url.setObjectName("label_url")
        self.label_3 = QtWidgets.QLabel(self.tab_1)
        self.label_3.setGeometry(QtCore.QRect(10, 80, 72, 15))
        self.label_3.setObjectName("label_3")
        self.lineEdit_CrawlingCookie = QtWidgets.QLineEdit(self.tab_1)
        self.lineEdit_CrawlingCookie.setGeometry(QtCore.QRect(40, 110, 261, 41))
        self.lineEdit_CrawlingCookie.setObjectName("lineEdit_CrawlingCookie")
        self.tabWidget.addTab(self.tab_1, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.tableWidget_crawl = QtWidgets.QTableWidget(self.tab_2)
        self.tableWidget_crawl.setGeometry(QtCore.QRect(0, 0, 781, 521))
        self.tableWidget_crawl.setRowCount(0)
        self.tableWidget_crawl.setColumnCount(0)
        self.tableWidget_crawl.setObjectName("tableWidget_crawl")
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.label_2 = QtWidgets.QLabel(self.tab_3)
        self.label_2.setGeometry(QtCore.QRect(20, 50, 91, 41))
        self.label_2.setText("")
        self.label_2.setObjectName("label_2")
        self.pushButton_SQLInject = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_SQLInject.setGeometry(QtCore.QRect(660, 370, 91, 31))
        self.pushButton_SQLInject.setAutoRepeatDelay(305)
        self.pushButton_SQLInject.setObjectName("pushButton_SQLInject")
        self.lineEdit_target = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_target.setGeometry(QtCore.QRect(80, 60, 201, 31))
        self.lineEdit_target.setObjectName("lineEdit_target")
        self.lab_target = QtWidgets.QLabel(self.tab_3)
        self.lab_target.setGeometry(QtCore.QRect(10, 60, 31, 21))
        self.lab_target.setObjectName("lab_target")
        self.comboBox_select = QtWidgets.QComboBox(self.tab_3)
        self.comboBox_select.setGeometry(QtCore.QRect(0, 0, 91, 31))
        self.comboBox_select.setObjectName("comboBox_select")
        self.label = QtWidgets.QLabel(self.tab_3)
        self.label.setGeometry(QtCore.QRect(0, 390, 72, 15))
        self.label.setObjectName("label")
        self.listView_tip = QtWidgets.QListView(self.tab_3)
        self.listView_tip.setGeometry(QtCore.QRect(0, 430, 781, 111))
        self.listView_tip.setObjectName("listView_tip")
        self.lineEdit_Cookie = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_Cookie.setGeometry(QtCore.QRect(80, 100, 201, 31))
        self.lineEdit_Cookie.setObjectName("lineEdit_Cookie")
        self.lab_target_2 = QtWidgets.QLabel(self.tab_3)
        self.lab_target_2.setGeometry(QtCore.QRect(10, 110, 51, 21))
        self.lab_target_2.setObjectName("lab_target_2")
        self.pushButton_pull = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_pull.setGeometry(QtCore.QRect(510, 370, 141, 31))
        self.pushButton_pull.setAutoRepeatDelay(305)
        self.pushButton_pull.setObjectName("pushButton_pull")
        self.spinBox_thread = QtWidgets.QSpinBox(self.tab_3)
        self.spinBox_thread.setGeometry(QtCore.QRect(80, 141, 46, 31))
        self.spinBox_thread.setProperty("value", 1)
        self.spinBox_thread.setObjectName("spinBox_thread")
        self.lab_target_3 = QtWidgets.QLabel(self.tab_3)
        self.lab_target_3.setGeometry(QtCore.QRect(10, 150, 31, 21))
        self.lab_target_3.setObjectName("lab_target_3")
        self.listView_target = QtWidgets.QListView(self.tab_3)
        self.listView_target.setGeometry(QtCore.QRect(440, 50, 311, 311))
        self.listView_target.setObjectName("listView_target")
        self.pushButton_addurl = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_addurl.setGeometry(QtCore.QRect(280, 60, 131, 31))
        self.pushButton_addurl.setAutoRepeatDelay(305)
        self.pushButton_addurl.setObjectName("pushButton_addurl")
        self.lab_target_4 = QtWidgets.QLabel(self.tab_3)
        self.lab_target_4.setGeometry(QtCore.QRect(450, 30, 101, 21))
        self.lab_target_4.setObjectName("lab_target_4")
        self.tabWidget.addTab(self.tab_3, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.tableWidget_sql = QtWidgets.QTableWidget(self.tab_4)
        self.tableWidget_sql.setGeometry(QtCore.QRect(0, 10, 781, 521))
        self.tableWidget_sql.setObjectName("tableWidget_sql")
        self.tableWidget_sql.setColumnCount(0)
        self.tableWidget_sql.setRowCount(0)
        self.tabWidget.addTab(self.tab_4, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 791, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(2)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.pushButton_analyse.setText(_translate("MainWindow", "开始分析"))
        self.label_url.setText(_translate("MainWindow", "URL:"))
        self.label_3.setText(_translate("MainWindow", "Cookie"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_1), _translate("MainWindow", "爬取网页"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "爬取结果"))
        self.pushButton_SQLInject.setText(_translate("MainWindow", "开始"))
        self.lab_target.setText(_translate("MainWindow", "URL"))
        self.label.setText(_translate("MainWindow", "提示信息:"))
        self.lab_target_2.setText(_translate("MainWindow", "Cookie"))
        self.pushButton_pull.setText(_translate("MainWindow", "获取爬虫结果"))
        self.lab_target_3.setText(_translate("MainWindow", "线程"))
        self.pushButton_addurl.setText(_translate("MainWindow", "添加到攻击列表"))
        self.lab_target_4.setText(_translate("MainWindow", "攻击列表"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainWindow", "SQL注入"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_4), _translate("MainWindow", "注入结果"))
