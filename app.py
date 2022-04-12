import sys
import os
import re
import subprocess
from PyQt5.QtWidgets import QApplication,QMainWindow,QTableWidgetItem,QMessageBox

from PyQt5.QtCore import *

from main_window import *
import urllib.request,urllib.parse,urllib.error
from bs4 import BeautifulSoup
import threading
import time

threadFinish = []
class  CrawlThread(QtCore.QThread):
    window = None
    URL_ROOT = ""
    Cookie = ""
    _signal = pyqtSignal(int)  # pyqt signal
    def __init__(self,win,URL_ROOT,Cookie):
        super().__init__()
        self.window = win
        self.URL_ROOT = URL_ROOT
        self.Cookie = Cookie
    def __del__(self):
        self.wait()
    def run(self):
        self._signal.emit(1)  # send 1
    def startCrawling(self):
        user_agent = r'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36'
        headers = {'User-Agent': user_agent, 'Cookie': self.Cookie}
        # Open the URL and read the whole page
        request = urllib.request.Request(self.URL_ROOT, headers=headers)
        html = urllib.request.urlopen(request).read()
        # Parser the string
        soup = BeautifulSoup(html, "html.parser")
        # Retrieve all of the anchor tags
        # Returns a list of all the links
        tags = soup("a")
        self.window.lstCrawlingResult.clear()
        for tag in tags:
            self.window.lstCrawlingResult.append(urllib.parse.urljoin(self.URL_ROOT, tag.get('href', None)))
        self.window.lstCrawlingResult = list(set(self.window.lstCrawlingResult))
        self.window.showCrawlingResultTable()
        QMessageBox.information(self.window, "tip", "已完成!共有" + str(len(tags)) + "记录")



class SQLThread (QtCore.QThread):
    result = [] #Output result
    name = "" # thread name
    select = 0 # Get or Post flag
    iStart = 0 # current target
    iEnd = 0 #target quantity
    targets = [] # this list is url
    cookie = ""
    _signal = pyqtSignal(int) #pyqt signal
    def __init__(self,win,name,select,iStart,iEnd,targets,cookie):
        # threading.Thread.__init__(self)
        super().__init__()
        self.window = win
        self.name = name
        self.select = select
        self.iStart = iStart
        self.iEnd = iEnd
        self.targets = targets
        self.cookie = cookie

    def __del__(self):
        self.wait()
    def run(self):
        global threadFinish
        threadFinish =[]
        try:
            while self.iStart < self.iEnd:
                self.url =self.targets[self.iStart]
                retLstInject = self.inject()

                if  retLstInject != []:
                    self.window.lstResult.append(retLstInject)
                    self.window.addToTip(self.url + " -> 存在SQL注入!")

                else:
                    self.window.addToTip(self.url + " -> 不存在SQL注入!")
                self.iStart = self.iStart+1
            self.window.mut.lock()
            threadFinish.append(self.name)
            self._signal.emit(1)
            self.window.mut.unlock()

        except Exception as e:
            QMessageBox.information(self.window, "err", "run错误!")

    # slot fun
    def call_backlog(self,msg):
        global threadFinish
        if msg == 1 and len(threadFinish) == self.window.count:
            threadFinish= []
            self.window.showSQLTable()
            self.window.addToTip("完成扫描... ...")
            QMessageBox.information(self.window, "tip", "已完成!")



    # SQL injection function,return a characteristic value list
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


    # Exact eignvalue to judge whether it is injection,return a characteristic value list
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

    # Connection command parameters "-u url",return command string
    def chek_url(self, url):
        return "python sqlmap\sqlmap.py -u " + "\"" + url + "\""

    # Connection command parameters "--cookie",return command string
    def chek_cookies(self, cmd, cookie):
        if len(cookie) > 0:
            return cmd + " --cookie " + "\"" + cookie + "\""
        return cmd

    # Connection command parameters "--batch",return command string

    def chek_batch(self, cmd):
        return cmd + " --batch "

    # Connection command parameters "--froms",return command string
    def chek_forms(self, cmd):
        return cmd + " --forms"

    # Execution command result,return a output result string
    def ret_output(self, *popenargs, **kwargs):
        s = ""
        p = subprocess.Popen(*popenargs, **kwargs, stdout=subprocess.PIPE)
        for i in p.stdout.readlines():
            if i != b"\r\n":
                s += i.decode()
        return s



class Window (QMainWindow,Ui_MainWindow):
    lstTipView = []
    lstTargeView =[]
    modelTargetView= None
    modelTipView = None
    lstCrawlingResult = [] # SQL injection reslut,it's a list
    lstResult = [] # sql injection reslut list
    intSelect = 0 # Get or Post flag
    url = [] # it's a list,used to put URL
    nThread = [] # Thread number
    thread1 = None  # thread var
    thread2 = None
    threads = []
    count = 0
    mut = None
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.initWidget()
        self.connectSignalsSlots()

    # Add info to ListView
    def addToTip(self,info):
        self.lstTipView.append(info)
        self.modelTipView.setStringList(self.lstTipView)
        self.listView_tip.setModel(self.modelTipView)

    # Init Tip ListView
    def initTipList(self):
        self.modelTipView = QStringListModel()
        self.lstTipView = []
        self.modelTipView.setStringList(self.lstTipView)
        self.listView_tip.setModel(self.modelTipView)


    # Add info to Target ListView
    def addToTargetList(self,info):
        self.lstTargeView.append(info)
        self.modelTargetView.setStringList(self.lstTargeView)
        self.listView_target.setModel(self.modelTargetView)

    # Init Target List
    def initTargetList(self):
        self.modelTargetView = QStringListModel()
        self.lstTargeView = []
        self.modelTargetView.setStringList(self.lstTargeView)
        self.listView_target.setModel(self.modelTargetView)

    # remove Target
    def removeTargetItem(self,qModelIndex):
        try:
            e = self.lstTargeView[qModelIndex.row()]
            reply = QMessageBox.information(self, "删除提示", "是否删除"+ e,QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.lstTargeView.remove(e)
                self.modelTargetView.setStringList(self.lstTargeView)
                self.listView_target.setModel(self.modelTargetView)

        except Exception as e:
            QMessageBox.information(self, "err", "removeTargetItem错误!")


    # Init Widget
    def initWidget(self):
        self.initTipList()
        self.initTargetList()
        #add items to comboBox
        self.comboBox_select.addItems(["GET", "POST"])
        self.initTableWidgetCrawl(1,2)
        self.initTableWidgetSQL(1,4)

    # Init tableWidget_crawl
    def initTableWidgetCrawl(self,Row,Col):
        self.tableWidget_crawl.setRowCount(Row)
        self.tableWidget_crawl.setColumnCount(Col)
        self.tableWidget_crawl.setHorizontalHeaderLabels(['序号', 'URL'])
        self.tableWidget_crawl.setColumnWidth(0, 80)
        self.tableWidget_crawl.setColumnWidth(1, 300)
        self.tableWidget_crawl.verticalHeader().hide()


    # Init tableWidget_sql
    def initTableWidgetSQL(self,Row,Col):
        # sql inject result table
        self.tableWidget_sql.setRowCount(Row)
        self.tableWidget_sql.setColumnCount(Col)
        self.tableWidget_sql.setColumnWidth(1, 300)
        self.tableWidget_sql.setHorizontalHeaderLabels(['序号', '存在注入页面', "注入类型", "后端数据库类型"])
        self.tableWidget_sql.verticalHeader().hide()


    # Connection slot function
    def connectSignalsSlots(self):
        self.comboBox_select.currentIndexChanged[int].connect(self.setSelect)
        self.pushButton_analyse.clicked.connect(self.startAnalysis)
        self.pushButton_SQLInject.clicked.connect(self.SQLInject)
        self.pushButton_pull.clicked.connect(self.pullResult)
        self.pushButton_addurl.clicked.connect(self.addUrl)
        self.listView_target.clicked.connect(self.removeTargetItem)


    # get or post fun
    def setSelect(self,i):
        self.intSelect = i

    # Show SQLTable
    def showSQLTable(self):
        iLen = len(self.lstResult) # sql injection list len
        self.initTableWidgetSQL(iLen,4) # Set rows and cols
        for r1 in self.lstResult:
            for i in range(0,len(self.lstResult)):
                self.tableWidget_sql.setItem(i, 0, QTableWidgetItem(str(i+1)))  # the value of row i and column 0 is str(i+1)
                self.tableWidget_sql.setItem(i, 1, QTableWidgetItem(r1[0]['URL']))
                self.tableWidget_sql.setItem(i, 2, QTableWidgetItem(r1[0]['TYPE']))
                self.tableWidget_sql.setItem(i, 3, QTableWidgetItem(r1[0]['DBMS']))

    # Show CrawlingResultTable
    def showCrawlingResultTable(self):
        self.initTableWidgetCrawl(len(self.lstCrawlingResult),2)
        for i,v in zip(range(0,len(self.lstCrawlingResult)),self.lstCrawlingResult):
            self.tableWidget_crawl.setItem(i, 0, QTableWidgetItem(str(i+1)))
            self.tableWidget_crawl.setItem(i, 1, QTableWidgetItem(v))


    # pushButton_analyse slot fun,crawl to Web links.
    def startAnalysis(self):
        try:
            URL_ROOT = self.lineEdit_analyse_url.text().strip()
            Cookie =  self.lineEdit_CrawlingCookie.text().strip()
            # create thread
            self.thread2 = CrawlThread(self, URL_ROOT, Cookie)
            # connect sinal,slot fun is startCrawling
            self.thread2._signal.connect(self.thread2.startCrawling)
            # start thread
            self.thread2.start()

        except Exception as e:
            QMessageBox.information(self, "err", "startAnalysis错误!")


    # pushButton_pull slot fun,pull results from repile results
    def pullResult(self):
        self.lstTargeView = []
        try:
            len = self.tableWidget_crawl.rowCount()
            for i in range(0,len):
                el = self.tableWidget_crawl.item(i,1).text().strip('\n')
                self.addToTargetList(el)

            QMessageBox.information(self, "tip", "已完成!共有"+str(len)+"记录")
        except Exception as e:
            QMessageBox.information(self, "err", "pullResult错误!")

    def addUrl(self):
        self.url = self.lineEdit_target.text().strip()
        if self.url  in self.lstTargeView:
            QMessageBox.information(self, "提示", "已存在" +self.url)

        else:
            self.addToTargetList(self.url)


    # pushButton_SQLInject slot fun,SQL Injection
    def SQLInject(self):
        if(self.lstTargeView != []):
            self.mut = QMutex()
            self.addToTip("开始扫描... ...")
            self.tableWidget_sql.clear()
            # self.lstTargets = [i.strip() for i in self.lineEdit_target.text().split(";") if i != '']
            # Start Injection
            lenTarget = len(self.lstTargeView)
            cookie = self.lineEdit_Cookie.text().strip()
            #cookie = "csrftoken=uIFvkwDcZ9YkqbzYfomquzd7fpwnK1mkaVBHamQs4FjyVIXKuy0DWpL1FoWHC55L; PHPSESSID=uu6r6ut32qcabrclbe79v7qvni; security=low"
            self.nThread = int(self.spinBox_thread.text())  # thread num
            self.startInject(lenTarget,self.lstTargeView,cookie,self.intSelect)
        else:
            QMessageBox.information(self, "err", "空数据!")
            self.addToTip("停止扫描... ...")


    #start injection
    def startInject(self,lenTarget,nTargets,cookie,select):
        try:
            #number of copies
            self.count = self.nThread
            for i in range(0,self.nThread):
                if lenTarget >= self.nThread:
                    src = (len(nTargets)//self.nThread)*i
                    dst = (len(nTargets)// self.nThread) * (i +1)
                    nData= nTargets[src:dst]
                    if (i == self.nThread - 1):
                        src = (len(nTargets)//self.nThread)*i
                        nData = nTargets[src:]

                    thread = SQLThread(self, "t"+str(i), select, 0, len(nTargets)//self.nThread,nData, cookie)
                    thread._signal.connect(thread.call_backlog)
                    self.threads.append(thread)
                    thread.start()

                if  lenTarget < self.nThread:
                    self.count = lenTarget
                    for j in range(0,lenTarget):
                        thread = SQLThread(self, "t" + str(j), select, j, j+1,nTargets[j:j+1] , cookie)
                        thread._signal.connect(thread.call_backlog)
                        self.threads.append(thread)
                        thread.start()
                    break
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


