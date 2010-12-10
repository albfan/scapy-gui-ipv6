#!/usr/bin/python
# -*- coding:utf-8 -*-

######################################################
##
## 1.0
##
######################################################

import sys
from PyQt4 import QtCore, QtGui, Qt
from scapy.all import *

class EH(QtGui.QDialog):
    """Extension Header Routing"""
    def __init__(self, ExtHdr):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Extension Header")
        self.ExtHdr = ExtHdr

        self.Label = QtGui.QLabel("Extension Header:", self)
        self.Label.setGeometry(QtCore.QRect(5, 5, 300, 30))
        self.comboBox = QtGui.QComboBox(self)
        self.comboBox.insertItem(0, 'Hop By Hop Options')
        self.comboBox.insertItem(1, 'Destination Options')
        self.comboBox.insertItem(2, 'Routing')
        self.comboBox.insertItem(3, 'Fragmentation')
        self.comboBox.setGeometry(QtCore.QRect(10, 30, 250, 31))

        self.Widget = QtGui.QWidget(self)
        self.Widget.setGeometry(QtCore.QRect(0, 60, 400, 300))
        self.Widget_Label = QtGui.QLabel("Hop By Hop addresses:", self.Widget)
        self.Widget_Label.setGeometry(QtCore.QRect(5, 10, 300, 30))
        self.Widget_tableWidget = QtGui.QTableWidget(0, 1, self.Widget)
        self.Widget_tableWidget.setHorizontalHeaderLabels(["Hop By Hop"])
        self.Widget_tableWidget.setColumnWidth(0,200)
        self.Widget_tableWidget.setGeometry(QtCore.QRect(10, 40, 250, 200))
        self.Widget_lineEdit = QtGui.QLineEdit(self.Widget)
        self.Widget_lineEdit.setGeometry(QtCore.QRect(10, 250, 250, 31))
        self.Widget_PushButton = QtGui.QPushButton("Add",self.Widget)
        self.Widget_PushButton.setGeometry(QtCore.QRect(270, 250, 98, 27))
        self.Widget_PushButton_2 = QtGui.QPushButton("Delete",self.Widget)
        self.Widget_PushButton_2.setGeometry(QtCore.QRect(270, 215, 98, 27))
        self.connect(self.Widget_PushButton, QtCore.SIGNAL('clicked()'), self.AddIP)
        self.connect(self.Widget_PushButton_2, QtCore.SIGNAL('clicked()'), self.DeleteIP)

        self.Widget_2 = QtGui.QWidget(self)
        self.Widget_2.setGeometry(QtCore.QRect(0, 60, 400, 300))
        self.Widget2_Label = QtGui.QLabel("Destination addresses:", self.Widget_2)
        self.Widget2_Label.setGeometry(QtCore.QRect(5, 10, 300, 30))
        self.Widget2_tableWidget = QtGui.QTableWidget(0, 1, self.Widget_2)
        self.Widget2_tableWidget.setHorizontalHeaderLabels(["Destination addresses"])
        self.Widget2_tableWidget.setColumnWidth(0,200)
        self.Widget2_tableWidget.setGeometry(QtCore.QRect(10, 40, 250, 200))
        self.Widget2_lineEdit = QtGui.QLineEdit(self.Widget_2)
        self.Widget2_lineEdit.setGeometry(QtCore.QRect(10, 250, 250, 31))
        self.Widget2_PushButton = QtGui.QPushButton("Add",self.Widget_2)
        self.Widget2_PushButton.setGeometry(QtCore.QRect(270, 250, 98, 27))
        self.Widget2_PushButton_2 = QtGui.QPushButton("Delete",self.Widget_2)
        self.Widget2_PushButton_2.setGeometry(QtCore.QRect(270, 215, 98, 27))
        self.connect(self.Widget2_PushButton, QtCore.SIGNAL('clicked()'), self.AddIP2)
        self.connect(self.Widget2_PushButton_2, QtCore.SIGNAL('clicked()'), self.DeleteIP2)

        self.Widget_3 = QtGui.QWidget(self)
        self.Widget_3.setGeometry(QtCore.QRect(0, 60, 400, 300))
        self.Widget3_Label = QtGui.QLabel("Routing Hop addresses:", self.Widget_3)
        self.Widget3_Label.setGeometry(QtCore.QRect(5, 10, 300, 30))
        self.Widget3_tableWidget = QtGui.QTableWidget(0, 1, self.Widget_3)
        self.Widget3_tableWidget.setHorizontalHeaderLabels(["Routing Hop"])
        self.Widget3_tableWidget.setColumnWidth(0,200)
        self.Widget3_tableWidget.setGeometry(QtCore.QRect(10, 40, 250, 200))
        self.Widget3_lineEdit = QtGui.QLineEdit(self.Widget_3)
        self.Widget3_lineEdit.setGeometry(QtCore.QRect(10, 250, 250, 31))
        self.Widget3_PushButton = QtGui.QPushButton("Add",self.Widget_3)
        self.Widget3_PushButton.setGeometry(QtCore.QRect(270, 250, 98, 27))
        self.Widget3_PushButton_2 = QtGui.QPushButton("Delete",self.Widget_3)
        self.Widget3_PushButton_2.setGeometry(QtCore.QRect(270, 215, 98, 27))
        self.connect(self.Widget3_PushButton, QtCore.SIGNAL('clicked()'), self.AddIP3)
        self.connect(self.Widget3_PushButton_2, QtCore.SIGNAL('clicked()'), self.DeleteIP3)

        self.Widget_4 = QtGui.QWidget(self)
        self.Widget_4.setGeometry(QtCore.QRect(0, 60, 400, 200))
        self.Widget4_Label = QtGui.QLabel("Identification:", self.Widget_4)
        self.Widget4_Label.setGeometry(QtCore.QRect(5, 10, 300, 30))
        self.Widget4_lineEdit = QtGui.QLineEdit(self.Widget_4)
        self.Widget4_lineEdit.setGeometry(QtCore.QRect(10, 35, 300, 31))
        self.Widget4_CheckBox = QtGui.QCheckBox("Last Package", self.Widget_4)
        self.Widget4_CheckBox.setGeometry(QtCore.QRect(10, 80, 116, 22))
        
        self.Widget.setVisible(False)
        self.Widget_2.setVisible(False)
        self.Widget_3.setVisible(False)
        self.Widget_4.setVisible(False)

        if self.ExtHdr[0] == '':
            self.Widget.setVisible(True)
        elif self.ExtHdr[0] == 'Hop By Hop Options':
            self.comboBox.setCurrentIndex(0)
            self.Widget.setVisible(True)
            i = len(self.ExtHdr[1])
            for d in range(i):
                self.Widget_tableWidget.insertRow(d)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[1][d])
                self.Widget_tableWidget.setItem(d, 0, t1)
        elif self.ExtHdr[0] == 'Destination Options':
            self.comboBox.setCurrentIndex(1)
            self.Widget_2.setVisible(True)
            i = len(self.ExtHdr[1])
            for d in range(i):
                self.Widget2_tableWidget.insertRow(d)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[1][d])
                self.Widget2_tableWidget.setItem(d, 0, t1)
        elif self.ExtHdr[0] == 'Routing':
            self.comboBox.setCurrentIndex(2)
            self.Widget_3.setVisible(True)
            i = len(self.ExtHdr[1])
            for d in range(i):
                self.Widget3_tableWidget.insertRow(d)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[1][d])
                self.Widget3_tableWidget.setItem(d, 0, t1)
        elif self.ExtHdr[0] == 'Fragmentation':
            self.comboBox.setCurrentIndex(3)
            self.Widget_4.setVisible(True)
            self.Widget4_lineEdit.setText(str(self.ExtHdr[1]))
            if self.ExtHdr[2] == True:
                self.Widget4_CheckBox.setChecked(True)
             

        self.connect(self.comboBox, QtCore.SIGNAL('activated(int)'), self.EHConf)
        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(111, 350, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        self.show()
 
    def EHConf(self):
        if self.comboBox.currentText() == 'Hop By Hop Options':
            self.Widget.setVisible(True)
            self.Widget_2.setVisible(False)
            self.Widget_3.setVisible(False)
            self.Widget_4.setVisible(False)
        elif self.comboBox.currentText() == 'Destination Options':
            self.Widget.setVisible(False)
            self.Widget_2.setVisible(True)
            self.Widget_3.setVisible(False)
            self.Widget_4.setVisible(False)
        elif self.comboBox.currentText() == 'Routing':
            self.Widget.setVisible(False)
            self.Widget_2.setVisible(False)
            self.Widget_3.setVisible(True)
            self.Widget_4.setVisible(False)
        elif self.comboBox.currentText() == 'Fragmentation':
            self.Widget.setVisible(False)
            self.Widget_2.setVisible(False)
            self.Widget_3.setVisible(False)
            self.Widget_4.setVisible(True)

    def AddIP(self):
        numRows = self.Widget_tableWidget.rowCount()
        if numRows < 16:
            self.Widget_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.Widget_lineEdit.text())
            self.Widget_tableWidget.setItem(numRows, 0, t1)
        else:
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")

    def DeleteIP(self):
        Row = self.Widget_tableWidget.currentRow()
        if Row >= 0:
            self.Widget_tableWidget.removeRow(Row)

    def AddIP2(self):
        numRows = self.Widget2_tableWidget.rowCount()
        if numRows < 16:
            self.Widget2_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.Widget2_lineEdit.text())
            self.Widget2_tableWidget.setItem(numRows, 0, t1)
        else:
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")

    def DeleteIP2(self):
        Row = self.Widget2_tableWidget.currentRow()
        if Row >= 0:
            self.Widget2_tableWidget.removeRow(Row)

    def AddIP3(self):
        numRows = self.Widget3_tableWidget.rowCount()
        if numRows < 16:
            self.Widget3_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.Widget3_lineEdit.text())
            self.Widget3_tableWidget.setItem(numRows, 0, t1)
        else:
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")

    def DeleteIP3(self):
        Row = self.Widget3_tableWidget.currentRow()
        if Row >= 0:
            self.Widget3_tableWidget.removeRow(Row)

    def fertig(self):
        self.ExtHdr[0] = self.comboBox.currentText()
        self.addresses=[]
        if self.ExtHdr[0] == 'Hop By Hop Options':
            i = self.Widget_tableWidget.rowCount()
            if i > 0:
                for d in range(i):
                    self.addresses.append([])
                    self.addresses[d] = str(QtGui.QTableWidgetItem.text(self.Widget_tableWidget.item(d, 0)))
                self.ExtHdr[1] = self.addresses
            else:
                self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Min one addresse is requiered!")
        elif self.ExtHdr[0] == 'Destination Options':
            i = self.Widget2_tableWidget.rowCount()
            if i > 0:
                for d in range(i):
                    self.addresses.append([])
                    self.addresses[d] = str(QtGui.QTableWidgetItem.text(self.Widget2_tableWidget.item(d, 0)))
                self.ExtHdr[1] = self.addresses
            else:
                self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Min one addresse is requiered!")
        elif self.ExtHdr[0] == 'Routing':
            i = self.Widget3_tableWidget.rowCount()
            if i > 0:
                for d in range(i):
                    self.addresses.append([])
                    self.addresses[d] = str(QtGui.QTableWidgetItem.text(self.Widget3_tableWidget.item(d, 0)))
                self.ExtHdr[1] = self.addresses
            else:
                self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Min one addresse is requiered!")
        elif self.ExtHdr[0] == 'Fragmentation':
            self.ExtHdr[1] = int(self.Widget4_lineEdit.text())
            self.ExtHdr[2] = self.Widget4_CheckBox.isChecked()
        #    self.err_msg = QtGui.QMessageBox.information(None, "Info!", "The Routing Address is requiered!")
        self.accept()

class RA(QtGui.QDialog):
    """Router Advertisement"""
    def __init__(self,RAconf):
        QtGui.QDialog.__init__(self)

        self.setWindowTitle("Router Advertisement")
        self.resize(320, 300)
        self.RAconf = RAconf

        self.Label = QtGui.QLabel("Prefix:", self)
        self.Label.setGeometry(QtCore.QRect(5, 15, 300, 30))
        self.Label_2 = QtGui.QLabel("Prefix lenght:", self)
        self.Label_2.setGeometry(QtCore.QRect(5, 85, 300, 30))
        self.line = QtGui.QFrame(self)
        self.line.setGeometry(QtCore.QRect(5, 150, 310, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.Label_3 = QtGui.QLabel("optional:", self)
        self.Label_3.setGeometry(QtCore.QRect(125, 160, 100, 30))
        self.Label_4 = QtGui.QLabel("ICMPv6 Option (Source Link-Layer-Address):", self)
        self.Label_4.setGeometry(QtCore.QRect(5, 190, 300, 30))
        self.lineEdit = QtGui.QLineEdit(self)
        self.lineEdit.setGeometry(QtCore.QRect(10, 40, 300, 31))
        self.lineEdit.setText(self.RAconf['Prefix'])
        self.lineEdit_2 = QtGui.QLineEdit(self)
        self.lineEdit_2.setGeometry(QtCore.QRect(10, 110, 60, 31))
        self.lineEdit_2.setText(self.RAconf['Prefixlen'])
        self.comboBox = QtGui.QComboBox(self)
        self.comboBox.setGeometry(QtCore.QRect(10, 215, 300, 31))
        self.comboBox.setEditable(True)

        ## init cbSrcLLaddr
        iflist = get_if_list()
        i = len(iflist)
        self.comboBox.insertItem(0, '')
        for d in range(0, i):
            self.comboBox.insertItem(i+1, get_if_hwaddr(iflist[d]))
        self.comboBox.setEditText(self.RAconf['SourceLL'])

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(111, 260, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        self.show()
 
    def fertig(self):
        self.RAconf['Prefix'] = self.lineEdit.text()
        self.RAconf['Prefixlen'] = self.lineEdit_2.text()
        self.RAconf['SourceLL'] = self.comboBox.currentText()
        if ((self.RAconf['Prefix'] == '' or None) or 
            (self.RAconf['Prefixlen'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Prefix and Prefix length are requiered!")
        self.accept()

class Payload(QtGui.QDialog):
    """Router Advertisement"""
    def __init__(self,PayloadFile):
        QtGui.QDialog.__init__(self)

        self.setWindowTitle("Packet Too Big")
        self.resize(420, 200)
        self.PayloadFile = PayloadFile

        self.Label = QtGui.QLabel("Define a packet which will be used as payload.", self)
        self.Label.setGeometry(QtCore.QRect(5, 0, 320, 30))
        self.Label_2 = QtGui.QLabel("Capture File:", self)
        self.Label_2.setGeometry(QtCore.QRect(5, 35, 300, 30))
        self.Label_3 = QtGui.QLabel("Packet No.:", self)
        self.Label_3.setGeometry(QtCore.QRect(5, 105, 300, 30))
        self.lineEdit = QtGui.QLineEdit(self.PayloadFile['Capture File'], self)
        self.lineEdit.setGeometry(QtCore.QRect(10, 70, 301, 27))
        self.lineEdit_2 = QtGui.QLineEdit(self.PayloadFile['Packet No.'], self)
        self.lineEdit_2.setGeometry(QtCore.QRect(10, 130, 113, 27))
        self.pushButton = QtGui.QPushButton("Search...", self)
        self.pushButton.setGeometry(QtCore.QRect(310, 70, 98, 27))
        self.connect(self.pushButton, QtCore.SIGNAL('clicked(bool)'), self.ask_for_filename)

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(161, 160, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        
        self.show()

    def ask_for_filename(self):
        self.fileDialog = QtGui.QFileDialog.getOpenFileName(self,"FileDialog")
	self.lineEdit.setText(self.fileDialog)
 
    def fertig(self):
        self.PayloadFile['Capture File'] = self.lineEdit.text()
        self.PayloadFile['Packet No.'] = self.lineEdit_2.text()
        
        self.accept()

class Main(QtGui.QMainWindow):

    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        self.setWindowTitle("Scapy Tool fuer Sicherheitstest")
        self.resize(500, 390)
        self.makeActions()
        self.makeMenu()

        self.EthH = {'LLSourceAddr':None,'LLDstAddr':None}
        self.IPH = {'Dst':None,'SourceIP':None,'NextHeader':None}
        self.ICMP = {'Type':'128'}
        self.RAconf = {'Prefix':'','Prefixlen':'','SourceLL':''}
        self.IPv6packet = {'EthHeader':None,'IPHeader':None,
                           'ExtHeader':None,'NextHeader':None}

        self.ExtHdr = [['','','']]
        self.PayloadFile = {'Capture File':'','Packet No.':'1'}
        self.sourcecode = None ## var to display the sourcecode 

        # Statuszeile
        self._label = QtGui.QLabel(u"Firewalltests")
        self.statusBar().addWidget(self._label)

        # TabWidget
        self.tabWidget = QtGui.QTabWidget(self)
        self.tabWidget.setGeometry(QtCore.QRect(0, 25, 500, 300))

	    # Ertes Tab - Ethernet Header
        self.tab = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab, "Ethernet Header (optional)")
        self.tab1_Label = QtGui.QLabel("All fields are optional.", self.tab)
        self.tab1_Label.setGeometry(QtCore.QRect(5, 0, 300, 30))
        self.tab1_Label_2 = QtGui.QLabel("Interface:", self.tab)
        self.tab1_Label_2.setGeometry(QtCore.QRect(5, 35, 300, 30))
        self.tab1_Label_3 = QtGui.QLabel("Destination Link Layer Address:", self.tab)
        self.tab1_Label_3.setGeometry(QtCore.QRect(5, 105, 300, 30))
        self.tab1_Label_4 = QtGui.QLabel("Source Link Layer Address:", self.tab)
        self.tab1_Label_4.setGeometry(QtCore.QRect(5, 175, 300, 30))
        self.tab1_comboBox = QtGui.QComboBox(self.tab)
        self.tab1_comboBox.setGeometry(QtCore.QRect(10, 60, 300, 31))
        self.tab1_lineEdit = QtGui.QLineEdit(self.tab)
        self.tab1_lineEdit.setGeometry(QtCore.QRect(10, 130, 300, 31))
        self.tab1_comboBox_2 = QtGui.QComboBox(self.tab)
        self.tab1_comboBox_2.setGeometry(QtCore.QRect(10, 200, 300, 31))
        self.tab1_comboBox_2.setEditable(True)

        # Zweites Tab - IPv6 Header
        self.tab_2 = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_2, "IPv6 Header")
        self.tab2_Label = QtGui.QLabel("Destination IPv6-address (or name):", self.tab_2)
        self.tab2_Label.setGeometry(QtCore.QRect(5, 35, 300, 30))
        self.tab2_Label_2 = QtGui.QLabel("Source IPv6-address:", self.tab_2)
        self.tab2_Label_2.setGeometry(QtCore.QRect(5, 105, 300, 30))
        self.tab2_lineEdit = QtGui.QLineEdit(self.tab_2)
        self.tab2_lineEdit.setGeometry(QtCore.QRect(10, 60, 300, 31))
        self.tab2_lineEdit_2 = QtGui.QLineEdit(self.tab_2)
        self.tab2_lineEdit_2.setGeometry(QtCore.QRect(10, 130, 300, 31))

        # Drittes Tab - Next Header
        self.tab_3 = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_3, "Next Header")

            # TabWidget_2 im Dritten Tab
        self.tabWidget_2 = QtGui.QTabWidget(self.tab_3)
        self.tabWidget_2.setGeometry(QtCore.QRect(0, 0, 490, 260))

            # Erstes Tab im TabWidget_2 - Routing Header 0
        self.tab3_tab = QtGui.QWidget(self.tabWidget_2)
        self.tabWidget_2.addTab(self.tab3_tab, "Extension Header")
        self.tab3_tab1_tableWidget = QtGui.QTableWidget(0, 1, self.tab3_tab)
        self.tab3_tab1_tableWidget.setHorizontalHeaderLabels(["Extension Header"])
        self.tab3_tab1_tableWidget.setColumnWidth(0,300)
        self.tab3_tab1_tableWidget.setGeometry(QtCore.QRect(0, 0, 320, 200))
        self.tab3_tab1_PushButton = QtGui.QPushButton("Add", self.tab3_tab)
        self.tab3_tab1_PushButton.setGeometry(QtCore.QRect(350, 30, 98, 27))
        self.tab3_tab1_PushButton_2 = QtGui.QPushButton("Edit", self.tab3_tab)
        self.tab3_tab1_PushButton_2.setGeometry(QtCore.QRect(350, 60, 98, 27))
        self.tab3_tab1_PushButton_3 = QtGui.QPushButton("Delete", self.tab3_tab)
        self.tab3_tab1_PushButton_3.setGeometry(QtCore.QRect(350, 90, 98, 27))
        self.connect(self.tab3_tab1_PushButton, QtCore.SIGNAL('clicked(bool)'), self.slotAddExtHdr)
        self.connect(self.tab3_tab1_PushButton_2, QtCore.SIGNAL('clicked(bool)'), self.slotEditExtHdr)
        self.connect(self.tab3_tab1_PushButton_3, QtCore.SIGNAL('clicked(bool)'), self.slotDeleteExtHdr)

            # Zweites Tab im TabWidget_2 - ICMPv6
        self.tab3_tab_2 = QtGui.QWidget()
        self.tabWidget_2.addTab(self.tab3_tab_2, "ICMPv6")
        self.tab3_tab2_Label = QtGui.QLabel("select the ICMPv6 Type", self.tab3_tab_2)
        self.tab3_tab2_Label.setGeometry(QtCore.QRect(5, 0, 300, 30))
        self.tab3_tab2_Label_2 = QtGui.QLabel("MTU:", self.tab3_tab_2)
        self.tab3_tab2_Label_2.setGeometry(QtCore.QRect(180, 126, 60, 30))
        self.tab3_tab2_radioButton = QtGui.QRadioButton("Ping", self.tab3_tab_2)
        self.tab3_tab2_radioButton.setGeometry(QtCore.QRect(30, 50, 60, 22))
        self.tab3_tab2_radioButton.setChecked(True)
        self.tab3_tab2_radioButton_2 = QtGui.QRadioButton("Router Advertisement", self.tab3_tab_2)
        self.tab3_tab2_radioButton_2.setGeometry(QtCore.QRect(30, 90, 180, 22))
        self.connect(self.tab3_tab2_radioButton_2, QtCore.SIGNAL('clicked(bool)'), self.slotRouterAdvertisement)
        self.tab3_tab2_radioButton_3 = QtGui.QRadioButton("Packet Too Big", self.tab3_tab_2)
        self.tab3_tab2_radioButton_3.setGeometry(QtCore.QRect(30, 130, 130, 22))
        self.connect(self.tab3_tab2_radioButton_3, QtCore.SIGNAL('clicked(bool)'), self.slotPacket_Too_Big)
        self.tab3_tab2_lineEdit = QtGui.QLineEdit("1240", self.tab3_tab_2)
        self.tab3_tab2_lineEdit.setGeometry(QtCore.QRect(220, 130, 61, 21))

        # Send Button
        self.SendButton = QtGui.QPushButton("Send", self)
        self.SendButton.setGeometry(QtCore.QRect(200, 330, 98, 27))
        self.connect(self.SendButton, QtCore.SIGNAL('clicked(bool)'), self.Buildit)
        self.show()

        ## init cbIface
        iflist = get_if_list() 
        cbIface = self.tab1_comboBox
        i = 0
        self.tab1_comboBox.insertItem(i, '')
        for d in iflist:
            i = i+1
            self.tab1_comboBox.insertItem(i, d)

        ## init cbSrcLLaddr
        i = len(iflist)
        self.tab1_comboBox_2.insertItem(0, '')
        for d in range(0, i):
            self.tab1_comboBox_2.insertItem(i+1, get_if_hwaddr(iflist[d]))

    def makeActions(self):
        self._saveAction = QtGui.QAction("&Save", None)
        self._loadAction = QtGui.QAction("&Load", None)
        self._exitAction = QtGui.QAction("&Exit", None)
        self._HelpAction = QtGui.QAction("&Help", None)
        self.connect(self._saveAction, QtCore.SIGNAL('triggered()'), self.slotSave)
        self.connect(self._loadAction, QtCore.SIGNAL('triggered()'), self.slotLoad)
        self.connect(self._exitAction, QtCore.SIGNAL('triggered()'), self.slotClose)
        self.connect(self._HelpAction, QtCore.SIGNAL('triggered()'), self.slotHelp)

    def makeMenu(self):
        menuBar = self.menuBar()
        fileMenu = menuBar.addMenu("&Datei")
        fileMenu.addAction(self._saveAction)
        fileMenu.addAction(self._loadAction)
        fileMenu.addAction(self._exitAction)
        fileHelp = menuBar.addMenu("&Hilfe")
        fileHelp.addAction(self._HelpAction)

    def slotAddExtHdr(self):
        """Ruft die Einstellung der Extension Header auf"""
        self.tabWidget.setEnabled(False)
        self.SendButton.setEnabled(False)
        Rows = len(self.ExtHdr)
        eh = EH(self.ExtHdr[Rows-1])
        eh.exec_()
        if self.ExtHdr[Rows-1][0] != '':
            numRows = self.tab3_tab1_tableWidget.rowCount()
            self.tab3_tab1_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.ExtHdr[Rows-1][0])
            self.tab3_tab1_tableWidget.setItem(numRows, 0, t1)
            item = self.tab3_tab1_tableWidget.item(numRows, 0)
            item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
            self.ExtHdr.append(['','',''])
        self.tabWidget.setEnabled(True)
        self.SendButton.setEnabled(True)

    def slotEditExtHdr(self):
        Row = self.tab3_tab1_tableWidget.currentRow()
        if Row != -1:
            self.tabWidget.setEnabled(False)
            self.SendButton.setEnabled(False)
            eh = EH(self.ExtHdr[Row])
            eh.exec_()
            t1 = QtGui.QTableWidgetItem(self.ExtHdr[Row][0])
            self.tab3_tab1_tableWidget.setItem(Row, 0, t1)
            self.tabWidget.setEnabled(True)
            self.SendButton.setEnabled(True)

    def slotDeleteExtHdr(self):
        """Löscht den markierten Extension Header"""
        Row = self.tab3_tab1_tableWidget.currentRow()
        if Row >= 0:
            self.tab3_tab1_tableWidget.removeRow(Row)
            del self.ExtHdr[Row]
            self.tab3_tab1_tableWidget.setCurrentCell(Row,0)

    def slotRouterAdvertisement(self):
        """Ruft die Router Advertisement auf"""
        self.tabWidget.setEnabled(False)
        self.SendButton.setEnabled(False)
        ra = RA(self.RAconf)
        ra.exec_()
        if ((self.RAconf['Prefix'] == '' or None) or 
            (self.RAconf['Prefixlen'] == '' or None)):
             self.tab3_tab2_radioButton.setChecked(True)
        self.tabWidget.setEnabled(True)
        self.SendButton.setEnabled(True)

    def slotPacket_Too_Big(self):
        """Ruft die Paylaod Einstellungen auf"""
        self.tabWidget.setEnabled(False)
        self.SendButton.setEnabled(False)
        payload = Payload(self.PayloadFile)
        payload.exec_()
        if ((self.PayloadFile['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
        self.tabWidget.setEnabled(True)
        self.SendButton.setEnabled(True)

    def slotSave(self):
        """Wird aufgerufen, um alle eingestellten Daten zu speichern."""
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "")
        self.save = QtCore.QFile(filename)
        self.save.open(QtCore.QIODevice.ReadWrite)
        tab1 = (#self.tab1_comboBox.currentText() + '\n' +
                self.tab1_lineEdit.text() + '\n' +
                self.tab1_comboBox_2.currentText() + '\n' )
        tab2 = (self.tab2_lineEdit.text() + '\n' +
                self.tab2_lineEdit_2.text() + '\n')            
        tab3 = (str(self.tab3_tab2_radioButton.isChecked()) + '\n' +
                str(self.tab3_tab2_radioButton_2.isChecked()) + '\n' +
                str(self.tab3_tab2_radioButton_3.isChecked()) + '\n' +
                self.tab3_tab2_lineEdit.text() + '\n')
        RA = (self.RAconf['Prefix'] + '\n' +
                self.RAconf['Prefixlen'] + '\n' +
                self.RAconf['SourceLL'] + '\n')
        Payl = (self.PayloadFile['Capture File'] + '\n' +
                self.PayloadFile['Packet No.'] + '\n')
        i = len(self.ExtHdr)
        ExtHdr = (str(i-1) + '\n')
        for d in range(i-1):
            if self.ExtHdr[d][0] == 'Fragmentation':
                ExtHdr = (ExtHdr + self.ExtHdr[d][0] + '\n'
                            + self.ExtHdr[d][1] + '\n'
                            + str(self.ExtHdr[d][2]) + '\n')
            else:
                i2 = len(self.ExtHdr[d][1])
                ExtHdr = (ExtHdr + str(self.ExtHdr[d][0]) + '\n' + str(i2) +'\n')
                for d2 in range(i2):
                    ExtHdr = (ExtHdr + self.ExtHdr[d][1][d2] + '\n')
        msg = (tab1 + tab2 + tab3 + RA + Payl + ExtHdr)
        self.save.write(str(msg))
        self.save.close();

    def slotLoad(self):
        """Wird aufgerufen, um fruher eingestellten Daten zu laden."""
        filename = QtGui.QFileDialog.getOpenFileName(self,"Load File", "")
        self.load = QtCore.QFile(filename)
        self.load.open(QtCore.QIODevice.ReadOnly)
#        self.tab1_comboBox.setEditable(True)
 #       tmp = str(self.load.readLine())
  #      tmp = tmp[:tmp.find('\n')]
   #     self.tab1_comboBox.setEditText(tmp)
    #    self.tab1_comboBox.setEditable(False)
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.tab1_lineEdit.setText(tmp)
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.tab1_comboBox_2.setEditText(tmp)
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.tab2_lineEdit.setText(tmp)
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.tab2_lineEdit_2.setText(tmp)
        if self.load.readLine() == True:
            self.tab3_tab2_radioButton.setChecked(True)
        if self.load.readLine() == True:
            self.tab3_tab2_radioButton_2.setChecked(True)
        if self.load.readLine() == True:
            self.tab3_tab2_radioButton_3.setChecked(True)
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.tab3_tab2_lineEdit.setText(tmp)
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.RAconf['Prefix'] = tmp
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.RAconf['Prefixlen'] = tmp
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.RAconf['SourceLL'] = tmp
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.PayloadFile['Capture File'] = tmp
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        self.PayloadFile['Packet No.'] = tmp
        tmp = str(self.load.readLine())
        tmp = tmp[:tmp.find('\n')]
        i = int(tmp)
        for d in range(self.tab3_tab1_tableWidget.rowCount()):
            self.tab3_tab1_tableWidget.removeRow(0)
        self.ExtHdr = [['','','']]
        for d in range(i):
            tmp = str(self.load.readLine())
            tmp = tmp[:tmp.find('\n')]
            self.ExtHdr[d][0] = tmp
            numRows = self.tab3_tab1_tableWidget.rowCount()
            self.tab3_tab1_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
            self.tab3_tab1_tableWidget.setItem(numRows, 0, t1)
            item = self.tab3_tab1_tableWidget.item(numRows, 0)
            item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
            if self.ExtHdr[d][0] == 'Fragmentation':
                tmp = str(self.load.readLine())
                tmp = tmp[:tmp.find('\n')]
                self.ExtHdr[d][1] = tmp
                tmp = str(self.load.readLine())
                tmp = tmp[:tmp.find('\n')]
                self.ExtHdr[d][2] = tmp
                
            else:
                tmp = str(self.load.readLine())
                tmp = tmp[:tmp.find('\n')]
                i2 = int(tmp)
                addresses = []
                for d2 in range(i2):
                    addresses.append([''])
                    tmp = str(self.load.readLine())
                    tmp = tmp[:tmp.find('\n')]
                    addresses[d2] = tmp
                self.ExtHdr[d][1] = addresses
            self.ExtHdr.append(['','',''])

    def slotClose(self):
        """Wird aufgerufen, wenn das Fenster geschlossen wird"""
        ret = QtGui.QMessageBox.question(None, "Ende?", "Wollen Sie wirklich schon gehen?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if ret == QtGui.QMessageBox.Yes:
            self.close()

    def slotHelp(self):
        help = QtGui.QMessageBox.information(None, "Dies ist die Hilfe", "Die Hilfe entsteht noch!")

    def SetICMPv6Type(self,Type):
        self.ICMP['Type'] = Type

###################
## build ip packets

    def Buildit(self):

        ##################
        ## Ethernet Header

        enDstLLaddr = self.tab1_lineEdit

        if enDstLLaddr.text() != '':
            self.EthH['LLDstAddr'] = str(enDstLLaddr.text())
        else:
            self.EthH['LLDstAddr'] = None

        cbSrcLLaddr = self.tab1_comboBox_2

        if cbSrcLLaddr.currentText() != '':
            self.EthH['LLSourceAddr'] = str(cbSrcLLaddr.currentText())
        else:
            self.EthH['LLSourceAddr'] = None

        self.IPv6packet['EthHeader'] = Ether(dst=self.EthH['LLDstAddr'],
                                             src=self.EthH['LLSourceAddr'])

        ## sourcecode...
        if ((self.EthH['LLDstAddr'] != None) and (self.EthH['LLSourceAddr'] != None)):
            self.sourcecode = ('Ether(dst=\''+str(self.EthH['LLDstAddr'])+
                               '\', src=\''+str(self.EthH['LLSourceAddr'])+'\')')
        elif (self.EthH['LLDstAddr'] != None):
            self.sourcecode = ('Ether(dst=\''+str(self.EthH['LLDstAddr'])+'\')')
        elif (self.EthH['LLSourceAddr'] != None):
            self.sourcecode = ('Ether(src=\''+str(self.EthH['LLSourceAddr'])+'\')')
        elif ((self.EthH['LLDstAddr'] == None) and (self.EthH['LLSourceAddr'] == None)):
            self.sourcecode = ('Ether()')

        ##############
        ## IPv6 Header

        enDstIP =  self.tab2_lineEdit
        if enDstIP.text() != '':
            self.IPH['Dst'] = str(enDstIP.text())
        else:
            self.IPH['Dst'] = None
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Destination Address is requiered\nto create a valid package!")

        enSourceIP =  self.tab2_lineEdit_2
        if enSourceIP.text() != '':
            self.IPH['SourceIP'] = str(enSourceIP.text())
        else:
            self.IPH['SourceIP'] = None

        self.IPv6packet['IPHeader'] = IPv6(dst=self.IPH['Dst'],
                                           src=self.IPH['SourceIP'])

        ## sourcecode...
        if ((self.IPH['Dst'] != None) and (self.IPH['SourceIP'] != None)):
            self.sourcecode = (self.sourcecode+'/IPv6(dst=\''+self.IPH['Dst']+
                               '\', src=\''+self.IPH['SourceIP']+'\')')
        elif (self.IPH['Dst'] != None):
            self.sourcecode = (self.sourcecode+'/IPv6(dst=\''+self.IPH['Dst']+
                               '\')')
        elif (self.IPH['SourceIP'] != None):
            self.sourcecode = (self.sourcecode+'/IPv6(src=\''+
                               self.IPH['SourceIP']+'\')')
        elif ((self.IPH['Dst'] == None) and (self.IPH['SourceIP'] == None)):
            self.sourcecode = (self.sourcecode+'/IPv6()')

        ############################
        ## add extension header if set

        self.NumExtHdr = len(self.ExtHdr)
        if self.NumExtHdr > 0:
            self.IPv6packet['ExtHeader'] = self.BuildExtHdr(self.NumExtHdr)
        else:
            self.IPv6packet['ExtHeader'] = None

        ########################
        ## add the next header

        self.IPv6packet['NextHeader'] = self.BuildICMPv6()

        ############
        ## get iface

        cbIface =  self.tab1_comboBox
        if cbIface.currentText() != '':
            Interface = str(cbIface.currentText())
        else:
            Interface = None

        ##########
        ## send it

        if self.IPv6packet['ExtHeader'] == (None or ''):
            sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                  /self.IPv6packet['NextHeader'], iface = Interface)
        else:
            sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                  /self.IPv6packet['ExtHeader']/self.IPv6packet['NextHeader'],
                  iface = Interface)

        if Interface == None:
            self.sourcecode = self.sourcecode
        else:
            self.sourcecode = (self.sourcecode+
                               ', iface=\''+Interface+'\'')
        
        ## show sourcecode in info_msg:

        self.sourcecode = ('sendp('+self.sourcecode+')')
        disp_sourcecode = QtGui.QMessageBox.information(None, "Scapy Quellcode", "Scapy Quellcode:\n\n%s" % self.sourcecode )


    ###############
    ## Build Extension Header

    def  BuildExtHdr(self, Num):

        ExtensionHeader = ''
        for d in range(Num-1):
            if self.ExtHdr[d][0] == 'Hop By Hop Options':
                i = len(self.ExtHdr[d][1])
                if (self.ExtHdr[d][1][0] != '' or None):
                    self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrHopByHop(options=[\'' + self.ExtHdr[d][1][0])
                    if i > 1:
                        for d2 in range(i-1):
                            self.sourcecode = (self.sourcecode + '\',\'' +
                                               self.ExtHdr[d][1][d2+1])
                self.sourcecode = (self.sourcecode + '\'])')
            elif self.ExtHdr[d][0] == 'Destination Options':
                i = len(self.ExtHdr[d][1])
                if (self.ExtHdr[d][1][0] != '' or None):
                    self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrDestOpt(options=[\'' + self.ExtHdr[d][1][0])
                    if i > 1:
                        for d2 in range(i-1):
                            self.sourcecode = (self.sourcecode + '\',\'' +
                                               self.ExtHdr[d][1][d2+1])
                self.sourcecode = (self.sourcecode + '\'])')
            elif self.ExtHdr[d][0] == 'Routing':
                i = len(self.ExtHdr[d][1])
                if (self.ExtHdr[d][1][0] != '' or None):
                    self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrRouting(addresses=[\'' + self.ExtHdr[d][1][0])
                    if i > 1:
                        for d2 in range(i-1):
                            self.sourcecode = (self.sourcecode + '\',\'' +
                                               self.ExtHdr[d][1][d2+1])
                self.sourcecode = (self.sourcecode + '\'])')
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrRouting(addresses = self.ExtHdr[d][1])
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrRouting(addresses = self.ExtHdr[d][1])
            elif self.ExtHdr[d][0] == 'Fragmentation':
                if self.ExtHdr[d][2] == True:
                    self.M_Flag = '0'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = 0,
                                                    id = int(self.ExtHdr[d][1]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 0,
                                                    id = int(self.ExtHdr[d][1]))
                else:
                    self.M_Flag = '1'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = 1,
                                                    id = int(self.ExtHdr[d][1]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 1,
                                                    id = int(self.ExtHdr[d][1]))
                self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrFragment(m=' + 
                                  str(self.M_Flag) + ',id=' + 
                                  str(self.ExtHdr[d][1]) + ')')
        return(ExtensionHeader)

    ###############
    ## Build ICMPv6

    def BuildICMPv6(self):

        if self.tab3_tab2_radioButton.isChecked():
            self.ICMP['Type'] = '128'
            ICMPv6 = self.BuildICMPv6_Ping()
        elif self.tab3_tab2_radioButton_2.isChecked():
            self.ICMP['Type'] = '134'
            ICMPv6 = self.BuildICMPv6_RA()
        elif self.tab3_tab2_radioButton_3.isChecked():
            self.ICMP['Type'] = '2'
            ICMPv6 = self.BuildICMPv6_PacketTooBig()
        else:
            self.Fehler = QtGui.QMessageBox.information(None, '', 'Sorry ICMPv6 Type %s is not implemented yet.' %self.ICMP['Type'])

        return(ICMPv6)

    ## Router Advertisement

    def BuildICMPv6_RA(self):
        ra=ICMPv6ND_RA(chlim=255, H=0L, M=0L, O=1L,
                       routerlifetime=180, P=0L, retranstimer=0, prf=0L,
                       res=0L)

        prefix_info=ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L,
                                          len=4,
                                          prefix=str(self.RAconf['Prefix']),
                                          R=0L, validlifetime=1814400,
                                          prefixlen=int(self.RAconf['Prefixlen']),
                                          preferredlifetime=604800, type=3)

        ## if source link-layer-addr set

        if (self.RAconf['SourceLL'] != None) and (self.RAconf['SourceLL'] != ''):
            llad=ICMPv6NDOptSrcLLAddr(type=1, len=1,
                                      lladdr=str(self.RAconf['SourceLL']))

            self.sourcecode = (self.sourcecode+
                               '/ICMPv6ND_RA(chlim=255, H=0L, M=0L, O=1L, '+
                               'routerlifetime=180, P=0L, retranstimer=0, '+
                               'prf=0L, res=0L)'+
                               '/ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, '+
                               'L=1L, len=4, '+
                               'prefix=\''+self.RAconf['Prefix']+'\', '+
                               'R=0L, validlifetime=1814400, '+
                               'prefixlen='+self.RAconf['Prefixlen']+', '+
                               'preferredlifetime=604800, type=3)'+
                               '/ICMPv6NDOptSrcLLAddr(type=1, len=1, '+
                               'lladdr=\''+self.RAconf['SourceLL']+'\')')
            return(ra/prefix_info/llad)
        else:
            self.sourcecode = (self.sourcecode+
                               '/ICMPv6ND_RA(chlim=255, H=0L, M=0L, O=1L, '+
                               'routerlifetime=180, P=0L, retranstimer=0, '+
                               'prf=0L, res=0L)'+
                               '/ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, '+
                               'L=1L, len=4, '+
                               'prefix=\''+self.RAconf['Prefix']+'\', '+
                               'R=0L, validlifetime=1814400, '+
                               'prefixlen='+self.RAconf['Prefixlen']+', '+
                               'preferredlifetime=604800, type=3)')
            return(ra/prefix_info)

    ## Echo Request

    def BuildICMPv6_Ping(self):
        self.sourcecode = self.sourcecode+'/ICMPv6EchoRequest()'
        return(ICMPv6EchoRequest())

    ## Packet Too Big

    def BuildICMPv6_PacketTooBig(self):

        enMTU = self.tab3_tab2_lineEdit
        if enMTU.text() != '':
            MTU = enMTU.text()
        else:
            MTU = None
        q=ICMPv6PacketTooBig(mtu=int(MTU))
        self.sourcecode = self.sourcecode+'/ICMPv6PacketTooBig(mtu='+MTU+')'

        enPCAP = self.PayloadFile['Capture File']
        if enPCAP != '':
            path = enPCAP
            capture = rdpcap(path)
            enPCAPno = self.PayloadFile['Packet No.']
            if enPCAPno != '':
                no = int(enPCAPno)-1
            else:
                no = 0
            q = q/capture[no][IPv6]
            self.sourcecode = (self.sourcecode+'/rdpcap(\''+path+'\')['+
                               str(no)+'][IPv6]')
        return(q)

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    m = Main()
    app.exec_()
