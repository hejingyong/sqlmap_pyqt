import sys
import os
import re
import subprocess
from PyQt5.QtWidgets import QApplication,QMainWindow,QTableWidgetItem,QMessageBox
from PyQt5.QtCore import QStringListModel
from main_window import *
import urllib.request,urllib.parse,urllib.error
from bs4 import BeautifulSoup
import threading

class SQLThread(threading.Thread):
    select = 0
    count = 0
    id = 0
    targets = None
    url = None
    result = []

    def __init__(self,name,select,count,targets,cookie):
        threading.Thread.__init__(self)
        self.name = name
        self.select = select
        self.count = count
        self.targets = targets
        self.cookie = cookie


    def run(self):
        result = []
        while self.count < len(self.targets):
            self.url =self.targets[self.count]
            lstResult = self.inject()
            if lstResult != []:
                self.result.append(lstResult)
            self.count = self.count+1

    """
    SQL injection function
    return a characteristic value list
    """
    def inject(self):
        try:
            cmd = self.chek_url(self.url)
            cmd = self.chek_cookies(cmd, self.cookie)
            if 0 == self.select:
                cmd = self.chek_batch(cmd)

            else:
                cmd = self.chek_forms(cmd)
                cmd = self.chek_batch(cmd)

            return self.extract(self.url, self.ret_output(cmd, shell=True))

        except Exception as e:
            QMessageBox.information(self, "err", "inject错误!")

    """
    Exact eignvalue to judge whether it is injection
    return a characteristic value list
    """
    def extract(self, url, result):
        d = {}
        sqlResult = []
        DBMS = re.findall('back-end DBMS:.+', result)
        listType = re.findall("Type:.*-base.*", result)
        if len(DBMS) > 0: # find DBMS
            DBMS = DBMS[0][15:]
            d['URL'] = url
            d['DBMS'] = DBMS
            if len(listType) > 0: #find TYPE
                d['TYPE'] = listType[0][6:]
                sqlResult.append(d)
        return sqlResult

    """
    Connection command parameters "-u url"
    return command string
    """
    def chek_url(self, url):
        return "python sqlmap\sqlmap.py -u " + "\"" + url + "\""

    """
    Connection command parameters "--cookie"
    return command string
    """
    def chek_cookies(self, cmd, cookie):
        if len(cookie) > 0:
            return cmd + " --cookie " + "\"" + cookie + "\""
        return cmd

    """
    Connection command parameters "--batch"
    return command string
    """
    def chek_batch(self, cmd):
        return cmd + " --batch "

    """
    Connection command parameters "--froms"
    return command string
    """
    def chek_forms(self, cmd):
        return cmd + " --forms"

    """
    Execution command result
    return a output result string
    """
    def ret_output(self, *popenargs, **kwargs):
        s = ""
        p = subprocess.Popen(*popenargs, **kwargs, stdout=subprocess.PIPE)
        for i in p.stdout.readlines():
            if i != b"\r\n":
                s += i.decode()
        return s


class Window (QMainWindow,Ui_MainWindow,SQLThread):

    list = []
    model= None
    # it's a list
    lstCrawlingResult = []
    # SQL injection reslut,it's a list
    lstResult = []
    iSelect = 0
    #it's a list,used to put URL
    lstTargets = []

    def __init__(self,parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.initWidget()
        self.connectSignalsSlots()

    # Init Widget
    def initWidget(self):
        self.model = QStringListModel()
        #add items to comboBox
        self.comboBox_select.addItems(["GET", "POST"])
        self.initTableWidgetCrawl(1,2)
        self.initTableWidgetSQL(1,4)


    """
    Init tableWidget_crawl
    """
    def initTableWidgetCrawl(self,Row,Col):
        self.tableWidget_crawl.setRowCount(Row)
        self.tableWidget_crawl.setColumnCount(Col)
        self.tableWidget_crawl.setHorizontalHeaderLabels(['序号', 'URL'])
        self.tableWidget_crawl.setColumnWidth(0, 80)
        self.tableWidget_crawl.setColumnWidth(1, 300)
        self.tableWidget_crawl.verticalHeader().hide()

    """
    Init tableWidget_sql
    """
    def initTableWidgetSQL(self,Row,Col):
        # sql inject result table
        self.tableWidget_sql.setRowCount(Row)
        self.tableWidget_sql.setColumnCount(Col)
        self.tableWidget_sql.setColumnWidth(1, 300)
        self.tableWidget_sql.setHorizontalHeaderLabels(['序号', '存在注入页面', "注入类型", "后端数据库类型"])
        self.tableWidget_sql.verticalHeader().hide()

    """
    Connection slot function
    """
    def connectSignalsSlots(self):
        self.comboBox_select.currentIndexChanged[int].connect(self.setSelect)
        self.pushButton_analyse.clicked.connect(self.startAnalysis)
        self.pushButton_SQLInject.clicked.connect(self.SQLInject)
        self.pushButton_pull.clicked.connect(self.pullResult)

    def setSelect(self,i):
        self.iSelect = i


    """
    Show SQLTable
    """
    def showSQLTable(self):
        iLen = len(self.lstResult)
        self.initTableWidgetSQL(iLen,4)
        for r1 in self.lstResult:  # get r1
            for i in range(0,len(self.lstResult)):
                self.tableWidget_sql.setItem(i, 0, QTableWidgetItem(str(i)))
                self.tableWidget_sql.setItem(i, 1, QTableWidgetItem(r1[0]['URL']))
                self.tableWidget_sql.setItem(i, 2, QTableWidgetItem(r1[0]['TYPE']))
                self.tableWidget_sql.setItem(i, 3, QTableWidgetItem(r1[0]['DBMS']))


    """
    Show CrawlingResultTable
    """
    def showCrawlingResultTable(self):
        self.initTableWidgetCrawl(len(self.lstCrawlingResult),2)
        for i,v in zip(range(0,len(self.lstCrawlingResult)),self.lstCrawlingResult):
            self.tableWidget_crawl.setItem(i, 0, QTableWidgetItem(str(i+1)))
            self.tableWidget_crawl.setItem(i, 1, QTableWidgetItem(v))

    # Add info to ListView
    def add(self,info):
        self.list.append(info)
        self.model.setStringList(self.list)
        self.listView_tip.setModel(self.model)

    """
    pushButton_analyse slot fun,crawl to Web links.
    """
    def startAnalysis(self):
        try:
            URL_ROOT = self.lineEdit_analyse_url.text().strip()
            user_agent = r'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36'
            Cookie =  self.lineEdit_CrawlingCookie.text().strip()
            headers = {'User-Agent': user_agent,'Cookie':Cookie}
            #Open the URL and read the whole page
            request = urllib.request.Request(URL_ROOT, headers=headers)
            html = urllib.request.urlopen(request).read()
            #Parser the string
            soup = BeautifulSoup(html,"html.parser")
            # Retrieve all of the anchor tags
            # Returns a list of all the links
            tags = soup("a")
            self.lstCrawlingResult.clear()
            for tag in tags:
                self.lstCrawlingResult.append(urllib.parse.urljoin(URL_ROOT,tag.get('href',None)))
            self.showCrawlingResultTable()
            QMessageBox.information(self,"tip","已完成!共有"+str(len(tags))+"记录")
        except Exception as e:
            QMessageBox.information(self, "err", "startAnalysis错误!")



    """
    pushButton_pull slot fun,pull results from repile results
    """
    def pullResult(self):
        try:
            rc = self.tableWidget_crawl.rowCount()
            if rc > 0:
              self.lstCrawlingResult.append(self.tableWidget_crawl.item(0,1).text().strip('\n'))
            s = ';'.join(self.lstCrawlingResult)
            self.lineEdit_target.setText(s)
            QMessageBox.information(self, "tip", "已完成!共有"+str(rc)+"记录")
        except  Exception as e:
            QMessageBox.information(self, "err", "pullResult错误!")

    '''
    pushButton_SQLInject slot fun,SQL Injection
    '''
    def SQLInject(self):
        self.lstTargets.clear()
        self.count = 0
        self.tableWidget_sql.clear()
        self.lstTargets = [i for i in self.lineEdit_target.text().split(";") if i != '']
        try:

            # Start Injection
            targets_len =len(self.lstTargets)
            self.add("开始扫描... ...")
            aselect = self.iSelect
            aurl = self.lstTargets
            cookie = self.lineEdit_Cookie.text()
            thread = SQLThread("t1",aselect,0,aurl,cookie)
            thread.start()
            thread.join()
            self.lstResult = thread.result


            if (len(self.lstResult) > 0):
                self.add("存在SQL注入!")
            else:
                self.add("不存在SQL注入!")

            self.add("完成扫描... ...")
            self.showSQLTable()
            QMessageBox.information(self, "tip", "已完成!")
        except Exception as e:
            QMessageBox.information(self, "err", "SQLInject错误!")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    # MainWindow = QMainWindow()
    # ui = Ui_MainWindow()
    # ui.setupUi(MainWindow)
    # MainWindow.show()
    win = Window()
    win.show()
    sys.exit(app.exec_())
