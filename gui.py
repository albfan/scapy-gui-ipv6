#!/usr/bin/python
# -*- coding:utf-8 -*-

######################################################
##
## 1.2
##
######################################################

import sys
from PyQt4 import QtCore, QtGui, Qt
from scapy.all import *

class EH(QtGui.QDialog):
    """Extension Header"""
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
        

        self.Widget_2 = QtGui.QWidget(self)
        self.Widget_2.setGeometry(QtCore.QRect(0, 60, 400, 300))
        

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
        self.connect(self.Widget3_PushButton, QtCore.SIGNAL('clicked()'), self.AddIP)
        self.connect(self.Widget3_PushButton_2, QtCore.SIGNAL('clicked()'), self.DeleteIP)

        self.Widget_4 = QtGui.QWidget(self)
        self.Widget_4.setGeometry(QtCore.QRect(0, 60, 400, 200))
        self.Widget4_Label = QtGui.QLabel("Fragment Offset:", self.Widget_4)
        self.Widget4_Label.setGeometry(QtCore.QRect(5, 10, 300, 30))
        self.Widget4_lineEdit = QtGui.QLineEdit(self.Widget_4)
        self.Widget4_lineEdit.setGeometry(QtCore.QRect(10, 35, 300, 31))
        self.Widget4_Label_2 = QtGui.QLabel("Identification:", self.Widget_4)
        self.Widget4_Label_2.setGeometry(QtCore.QRect(5, 80, 300, 30))
        self.Widget4_lineEdit_2 = QtGui.QLineEdit(self.Widget_4)
        self.Widget4_lineEdit_2.setGeometry(QtCore.QRect(10, 105, 300, 31))
        self.Widget4_CheckBox = QtGui.QCheckBox("Last Package", self.Widget_4)
        self.Widget4_CheckBox.setGeometry(QtCore.QRect(10, 160, 116, 22))
        
        self.Widget.setVisible(False)
        self.Widget_2.setVisible(False)
        self.Widget_3.setVisible(False)
        self.Widget_4.setVisible(False)

        if self.ExtHdr[0] == '':
            self.Widget.setVisible(True)
        elif self.ExtHdr[0] == 'Hop By Hop Options':
            self.comboBox.setCurrentIndex(0)
            self.Widget.setVisible(True)

        elif self.ExtHdr[0] == 'Destination Options':
            self.comboBox.setCurrentIndex(1)
            self.Widget_2.setVisible(True)

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
            self.Widget4_lineEdit_2.setText(str(self.ExtHdr[1]))
            if self.ExtHdr[2] == 0:
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
        numRows = self.Widget3_tableWidget.rowCount()
        if numRows < 16:
            self.Widget3_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.Widget3_lineEdit.text())
            self.Widget3_tableWidget.setItem(numRows, 0, t1)
        else:
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")

    def DeleteIP(self):
        Row = self.Widget3_tableWidget.currentRow()
        if Row >= 0:
            self.Widget3_tableWidget.removeRow(Row)

    def fertig(self):
        self.ExtHdr[0] = self.comboBox.currentText()
        self.addresses=[]
            
        if self.ExtHdr[0] == 'Routing':
            i = self.Widget3_tableWidget.rowCount()
            if i > 0:
                for d in range(i):
                    self.addresses.append([])
                    self.addresses[d] = str(QtGui.QTableWidgetItem.text(self.Widget3_tableWidget.item(d, 0)))
                self.ExtHdr[1] = self.addresses
            else:
                self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Min one addresse is requiered!")
        elif self.ExtHdr[0] == 'Fragmentation':
            self.ExtHdr[1] = int(self.Widget4_lineEdit_2.text())
            if self.Widget4_CheckBox.isChecked() == True:
                self.ExtHdr[2] = 0
            else:
                self.ExtHdr[2] = 1
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
        if ((self.lineEdit.text() == '' or None) or 
            (self.lineEdit_2.text() == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Prefix and Prefix length are requiered!\n(Default: Prefix = 'fd00:141:64:1::'; Prefixlength = 32)")
        if self.RAconf['Prefix'] == None:
            self.lineEdit.setText(self.RAconf['Prefix'])
        else:
            self.lineEdit.setText('fd00:141:64:1::')
        if self.RAconf['Prefixlen'] == None:
            self.lineEdit_2.setText(self.RAconf['Prefixlen'])
        else:
            self.lineEdit_2.setText('32')
        self.RAconf['Prefix'] = self.lineEdit.text()
        self.RAconf['Prefixlen'] = self.lineEdit_2.text()
        self.RAconf['SourceLL'] = self.comboBox.currentText()
        
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
        self.resize(600, 390)
        self.makeActions()
        self.makeMenu()

        self.EthH = {'LLSourceAddr':None,'LLDstAddr':None}
        self.IPH = {'Dst':None,'SourceIP':None,'NextHeader':None}
        self.RAconf = {'Prefix':'fd00:141:64:1::','Prefixlen':'32','SourceLL':''}
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
        self.tabWidget.setGeometry(QtCore.QRect(0, 25, 600, 300))

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

        # Drittes Tab - Extension Header
        self.tab_3 = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_3, "Extension Header")
        self.tab3_tableWidget = QtGui.QTableWidget(0, 1, self.tab_3)
        self.tab3_tableWidget.setHorizontalHeaderLabels(["Extension Header"])
        self.tab3_tableWidget.setColumnWidth(0,300)
        self.tab3_tableWidget.setGeometry(QtCore.QRect(50, 10, 320, 250))
        self.tab3_PushButton = QtGui.QPushButton("Add", self.tab_3)
        self.tab3_PushButton.setGeometry(QtCore.QRect(420, 30, 98, 27))
        self.tab3_PushButton_2 = QtGui.QPushButton("Edit", self.tab_3)
        self.tab3_PushButton_2.setGeometry(QtCore.QRect(420, 60, 98, 27))
        self.tab3_PushButton_3 = QtGui.QPushButton("Delete", self.tab_3)
        self.tab3_PushButton_3.setGeometry(QtCore.QRect(420, 90, 98, 27))
        self.connect(self.tab3_PushButton, QtCore.SIGNAL('clicked(bool)'), self.slotAddExtHdr)
        self.connect(self.tab3_PushButton_2, QtCore.SIGNAL('clicked(bool)'), self.slotEditExtHdr)
        self.connect(self.tab3_PushButton_3, QtCore.SIGNAL('clicked(bool)'), self.slotDeleteExtHdr)

        # Viertes Tab - Next Header
        self.tab_4 = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_4, "Next Header")
        self.tab4_comboBox = QtGui.QComboBox(self.tab_4)
        self.tab4_comboBox.insertItem(0, 'ICMP')
        self.tab4_comboBox.insertItem(1, 'TCP')
        self.tab4_comboBox.insertItem(2, 'UDP')
        self.tab4_comboBox.insertItem(3, 'No Next Header')
        self.tab4_comboBox.setGeometry(QtCore.QRect(10, 30, 250, 31))
        self.tab4_Widget = QtGui.QWidget(self.tab_4)
        self.tab4_Widget.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.tab4_Widget_radioButton = QtGui.QRadioButton("Ping", self.tab4_Widget)
        self.tab4_Widget_radioButton.setGeometry(QtCore.QRect(30, 30, 60, 22))
        self.tab4_Widget_radioButton.setChecked(True)
        self.tab4_Widget_radioButton_2 = QtGui.QRadioButton("Router Advertisement", self.tab4_Widget)
        self.tab4_Widget_radioButton_2.setGeometry(QtCore.QRect(30, 70, 180, 22))
        self.connect(self.tab4_Widget_radioButton_2, QtCore.SIGNAL('clicked(bool)'), self.slotRouterAdvertisement)
        self.tab4_Widget_radioButton_3 = QtGui.QRadioButton("Packet Too Big", self.tab4_Widget)
        self.tab4_Widget_radioButton_3.setGeometry(QtCore.QRect(30, 110, 130, 22))
        self.connect(self.tab4_Widget_radioButton_3, QtCore.SIGNAL('clicked(bool)'), self.slotPacket_Too_Big)
        self.tab4_Widget_Label = QtGui.QLabel("MTU:", self.tab4_Widget)
        self.tab4_Widget_Label.setGeometry(QtCore.QRect(80, 136, 60, 30))
        self.tab4_Widget_lineEdit = QtGui.QLineEdit("1240", self.tab4_Widget)
        self.tab4_Widget_lineEdit.setGeometry(QtCore.QRect(120, 140, 61, 21))
        self.tab4_Widget_2 = QtGui.QWidget(self.tab_4)
        self.tab4_Widget_2.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.tab4_Widget_2.setVisible(False)
        self.tab4_Widget2_Label = QtGui.QLabel("Source Port:", self.tab4_Widget_2)
        self.tab4_Widget2_Label.setGeometry(QtCore.QRect(30, 30, 120, 30))
        self.tab4_Widget2_lineEdit = QtGui.QLineEdit("20", self.tab4_Widget_2)
        self.tab4_Widget2_lineEdit.setGeometry(QtCore.QRect(150, 34, 60, 21))
        self.tab4_Widget2_Label_2 = QtGui.QLabel("Destination Port:", self.tab4_Widget_2)
        self.tab4_Widget2_Label_2.setGeometry(QtCore.QRect(30, 70, 120, 30))
        self.tab4_Widget2_lineEdit_2 = QtGui.QLineEdit("80", self.tab4_Widget_2)
        self.tab4_Widget2_lineEdit_2.setGeometry(QtCore.QRect(150, 74, 60, 21))
        self.tab4_Widget3_Label_3 = QtGui.QLabel("Payload:", self.tab4_Widget_2)
        self.tab4_Widget3_Label_3.setGeometry(QtCore.QRect(300, 0, 120, 30))
        self.tab4_Widget2_radioButton = QtGui.QRadioButton("String with 'X' * Length", self.tab4_Widget_2)
        self.tab4_Widget2_radioButton.setGeometry(QtCore.QRect(330, 30, 200, 22))
        self.tab4_Widget2_radioButton.setChecked(True)
        self.tab4_Widget2_Label_4 = QtGui.QLabel("Length:", self.tab4_Widget_2)
        self.tab4_Widget2_Label_4.setGeometry(QtCore.QRect(350, 50, 120, 30))
        self.tab4_Widget2_lineEdit_3 = QtGui.QLineEdit("1", self.tab4_Widget_2)
        self.tab4_Widget2_lineEdit_3.setGeometry(QtCore.QRect(400, 54, 60, 21))
        self.tab4_Widget2_radioButton_2 = QtGui.QRadioButton("String:", self.tab4_Widget_2)
        self.tab4_Widget2_radioButton_2.setGeometry(QtCore.QRect(330, 90, 200, 22))
        self.tab4_Widget2_lineEdit_4 = QtGui.QLineEdit("X", self.tab4_Widget_2)
        self.tab4_Widget2_lineEdit_4.setGeometry(QtCore.QRect(400, 91, 60, 21))
        self.tab4_Widget2_radioButton_3 = QtGui.QRadioButton("pcap File:", self.tab4_Widget_2)
        self.tab4_Widget2_radioButton_3.setGeometry(QtCore.QRect(330, 130, 200, 22))
        self.connect(self.tab4_Widget2_radioButton_3, QtCore.SIGNAL('clicked(bool)'), self.slotPayloadTCP)
        self.tab4_Widget2_radioButton_4 = QtGui.QRadioButton("No Payload", self.tab4_Widget_2)
        self.tab4_Widget2_radioButton_4.setGeometry(QtCore.QRect(330, 170, 200, 22))
        self.tab4_Widget_3 = QtGui.QWidget(self.tab_4)
        self.tab4_Widget_3.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.tab4_Widget_3.setVisible(False)
        self.tab4_Widget3_Label = QtGui.QLabel("Source Port:", self.tab4_Widget_3)
        self.tab4_Widget3_Label.setGeometry(QtCore.QRect(30, 30, 120, 30))
        self.tab4_Widget3_lineEdit = QtGui.QLineEdit("53", self.tab4_Widget_3)
        self.tab4_Widget3_lineEdit.setGeometry(QtCore.QRect(150, 34, 60, 21))
        self.tab4_Widget3_Label_2 = QtGui.QLabel("Destination Port:", self.tab4_Widget_3)
        self.tab4_Widget3_Label_2.setGeometry(QtCore.QRect(30, 70, 120, 30))
        self.tab4_Widget3_lineEdit_2 = QtGui.QLineEdit("53", self.tab4_Widget_3)
        self.tab4_Widget3_lineEdit_2.setGeometry(QtCore.QRect(150, 74, 60, 21))
        self.tab4_Widget3_Label_3 = QtGui.QLabel("Payload:", self.tab4_Widget_3)
        self.tab4_Widget3_Label_3.setGeometry(QtCore.QRect(300, 0, 120, 30))
        self.tab4_Widget3_radioButton = QtGui.QRadioButton("String with 'X' * Length", self.tab4_Widget_3)
        self.tab4_Widget3_radioButton.setGeometry(QtCore.QRect(330, 30, 200, 22))
        self.tab4_Widget3_radioButton.setChecked(True)
        self.tab4_Widget3_Label_4 = QtGui.QLabel("Length:", self.tab4_Widget_3)
        self.tab4_Widget3_Label_4.setGeometry(QtCore.QRect(350, 50, 120, 30))
        self.tab4_Widget3_lineEdit_3 = QtGui.QLineEdit("1", self.tab4_Widget_3)
        self.tab4_Widget3_lineEdit_3.setGeometry(QtCore.QRect(400, 54, 60, 21))
        self.tab4_Widget3_radioButton_2 = QtGui.QRadioButton("String:", self.tab4_Widget_3)
        self.tab4_Widget3_radioButton_2.setGeometry(QtCore.QRect(330, 90, 200, 22))
        self.tab4_Widget3_lineEdit_4 = QtGui.QLineEdit("X", self.tab4_Widget_3)
        self.tab4_Widget3_lineEdit_4.setGeometry(QtCore.QRect(400, 91, 60, 21))
        self.tab4_Widget3_radioButton_3 = QtGui.QRadioButton("pcap File:", self.tab4_Widget_3)
        self.tab4_Widget3_radioButton_3.setGeometry(QtCore.QRect(330, 130, 200, 22))
        self.connect(self.tab4_Widget3_radioButton_3, QtCore.SIGNAL('clicked(bool)'), self.slotPayloadUDP)
        self.tab4_Widget3_radioButton_4 = QtGui.QRadioButton("No Payload", self.tab4_Widget_3)
        self.tab4_Widget3_radioButton_4.setGeometry(QtCore.QRect(330, 170, 200, 22))
        self.tab4_Widget_4 = QtGui.QWidget(self.tab_4)
        self.tab4_Widget_4.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.tab4_Widget_4.setVisible(False)
        self.connect(self.tab4_comboBox, QtCore.SIGNAL('activated(int)'), self.NHConf)

        # Send Button
        self.SendButton = QtGui.QPushButton("Send", self)
        self.SendButton.setGeometry(QtCore.QRect(250, 330, 98, 27))
        self.connect(self.SendButton, QtCore.SIGNAL('clicked(bool)'), self.slotSend)
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

    def NHConf(self):
        if self.tab4_comboBox.currentText() == 'ICMP':
            self.tab4_Widget.setVisible(True)
            self.tab4_Widget_2.setVisible(False)
            self.tab4_Widget_3.setVisible(False)
            self.tab4_Widget_4.setVisible(False)
        elif self.tab4_comboBox.currentText() == 'TCP':
            self.tab4_Widget.setVisible(False)
            self.tab4_Widget_2.setVisible(True)
            self.tab4_Widget_3.setVisible(False)
            self.tab4_Widget_4.setVisible(False)
        elif self.tab4_comboBox.currentText() == 'UDP':
            self.tab4_Widget.setVisible(False)
            self.tab4_Widget_2.setVisible(False)
            self.tab4_Widget_3.setVisible(True)
            self.tab4_Widget_4.setVisible(False)
        elif self.tab4_comboBox.currentText() == 'No Next Header':
            self.tab4_Widget.setVisible(False)
            self.tab4_Widget_2.setVisible(False)
            self.tab4_Widget_3.setVisible(False)
            self.tab4_Widget_4.setVisible(True)

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
            numRows = self.tab3_tableWidget.rowCount()
            self.tab3_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.ExtHdr[Rows-1][0])
            self.tab3_tableWidget.setItem(numRows, 0, t1)
            item = self.tab3_tableWidget.item(numRows, 0)
            item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
            self.ExtHdr.append(['','',''])
        self.tabWidget.setEnabled(True)
        self.SendButton.setEnabled(True)

    def slotEditExtHdr(self):
        Row = self.tab3_tableWidget.currentRow()
        if Row != -1:
            self.tabWidget.setEnabled(False)
            self.SendButton.setEnabled(False)
            eh = EH(self.ExtHdr[Row])
            eh.exec_()
            t1 = QtGui.QTableWidgetItem(self.ExtHdr[Row][0])
            self.tab3_tableWidget.setItem(Row, 0, t1)
            self.tabWidget.setEnabled(True)
            self.SendButton.setEnabled(True)

    def slotDeleteExtHdr(self):
        """Löscht den markierten Extension Header"""
        Row = self.tab3_tableWidget.currentRow()
        if Row >= 0:
            self.tab3_tableWidget.removeRow(Row)
            del self.ExtHdr[Row]
            self.tab3_tableWidget.setCurrentCell(Row,0)

    def slotRouterAdvertisement(self):
        """Ruft die Router Advertisement auf"""
        self.tabWidget.setEnabled(False)
        self.SendButton.setEnabled(False)
        ra = RA(self.RAconf)
        ra.exec_()
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
            self.tab4_Widget_radioButton.setChecked(True)
        self.tabWidget.setEnabled(True)
        self.SendButton.setEnabled(True)

    def slotPayloadTCP(self):
        """Ruft die Paylaod Einstellungen auf"""
        self.tabWidget.setEnabled(False)
        self.SendButton.setEnabled(False)
        payload = Payload(self.PayloadFile)
        payload.exec_()
        if ((self.PayloadFile['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
            self.tab4_Widget2_radioButton.setChecked(True)
        self.tabWidget.setEnabled(True)
        self.SendButton.setEnabled(True)

    def slotPayloadUDP(self):
        """Ruft die Paylaod Einstellungen auf"""
        self.tabWidget.setEnabled(False)
        self.SendButton.setEnabled(False)
        payload = Payload(self.PayloadFile)
        payload.exec_()
        if ((self.PayloadFile['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
            self.tab4_Widget3_radioButton.setChecked(True)
        self.tabWidget.setEnabled(True)
        self.SendButton.setEnabled(True)

    def slotSave(self):
        """Wird aufgerufen, um alle eingestellten Daten zu speichern."""
#Destination Address!!!! abfragen!!!
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "",("pcap(*.cap)"))
        filename=(filename+'.cap')
        self.Buildit(1,filename)

    def slotLoad(self):
        """Wird aufgerufen, um früher eingestellten Daten zu laden."""
        filename = QtGui.QFileDialog.getOpenFileName(self,"Load File", "",("pcap(*.cap)"))
        Packet = rdpcap(str(filename))
        Data = Packet[0]
        Data.show2()
        self.tab1_lineEdit.setText(Data[0].dst)
        self.tab1_comboBox_2.setEditText(Data[0].src)
        self.tab2_lineEdit.setText(Data[1].dst)
        self.tab2_lineEdit_2.setText(Data[1].src)
        Data = Data[1]
        self.NextHeader = Data.nh
        Data = Data[1]
        for d in range(self.tab3_tableWidget.rowCount()):
            self.tab3_tableWidget.removeRow(0)
        self.ExtHdr = [['','','']]
        d = 0
        temp = 0
        count = 0
        while count < 1:
            if self.NextHeader == 0:
                temp = Data.nh
                self.ExtHdr[d][0] = 'Hop By Hop Options'
                numRows = self.tab3_tableWidget.rowCount()
                self.tab3_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.tab3_tableWidget.setItem(numRows, 0, t1)
                item = self.tab3_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
                self.ExtHdr.append(['','',''])
                d = d + 1
                if len(Data) == Data.len + 8:
                    count = 1
                else:
                    count = 0
                Data = Data[2]
            elif self.NextHeader == 43:
                temp = Data.nh
                self.ExtHdr[d][0] = 'Routing'
                self.ExtHdr[d][1] = Data.addresses
                numRows = self.tab3_tableWidget.rowCount()
                self.tab3_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.tab3_tableWidget.setItem(numRows, 0, t1)
                item = self.tab3_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
                self.ExtHdr.append(['','',''])
                d = d + 1
                count = 0
                Data = Data[1]
            elif self.NextHeader == 44:
                temp = Data.nh
                self.ExtHdr[d][0] = 'Fragmentation'
                self.ExtHdr[d][1] = Data.id
                self.ExtHdr[d][2] = Data.m
                numRows = self.tab3_tableWidget.rowCount()
                self.tab3_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.tab3_tableWidget.setItem(numRows, 0, t1)
                item = self.tab3_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
                self.ExtHdr.append(['','',''])
                d = d + 1
                count = 0
                Data = Data[1]
            elif self.NextHeader == 60:
                temp = Data.nh
                self.ExtHdr[d][0] = 'Destination Options'
                numRows = self.tab3_tableWidget.rowCount()
                self.tab3_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.tab3_tableWidget.setItem(numRows, 0, t1)
                item = self.tab3_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
                self.ExtHdr.append(['','',''])
                d = d + 1
                if len(Data) == Data.len + 8:
                    count = 1
                else:
                    count = 0
                Data = Data[2]
            elif self.NextHeader == 58:
                self.tab4_comboBox.setCurrentIndex(0)
                self.NHConf()
                if Data.type == 128:
                    self.tab4_Widget_radioButton.setChecked(True)
                elif Data.type == 134:
                    self.tab4_Widget_radioButton_2.setChecked(True)
                    self.RAconf['Prefix'] = Data.prefix
                    self.RAconf['Prefixlen'] = Data.prefixlen
                elif Data.type == 2:
                    self.tab4_Widget_radioButton_3.setChecked(True)
                count = 1
            elif self.NextHeader == 6:
                self.tab4_comboBox.setCurrentIndex(1)
                self.NHConf()
                self.tab4_Widget2_lineEdit.setText(str(Data.sport))
                self.tab4_Widget2_lineEdit_2.setText(str(Data.dport))
                count = 1
            elif self.NextHeader == 17:
                self.tab4_comboBox.setCurrentIndex(2)
                self.NHConf()
                self.tab4_Widget3_lineEdit.setText(str(Data.sport))
                self.tab4_Widget3_lineEdit_2.setText(str(Data.dport))
                count = 1
            elif self.NextHeader == 59:
                self.tab4_comboBox.setCurrentIndex(3)
                self.NHConf()
                count = 1
            else:
                count = 1
            self.NextHeader = temp

    def slotSend(self):
        self.Buildit(0,'')

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

    def Buildit(self,Type,File):

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

        self.IPv6packet['NextHeader'] = self.BuildNextHeader()

        ############
        ## get iface

        cbIface =  self.tab1_comboBox
        if cbIface.currentText() != '':
            Interface = str(cbIface.currentText())
        else:
            Interface = None

        ##########
        ## send or save it

        if Type == 0:
            ## send
            if self.IPv6packet['ExtHeader'] == (None or ''):
                if self.IPv6packet['NextHeader'] != None:
                    sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                          /self.IPv6packet['NextHeader'], iface = Interface)
                else:
                    sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                          , iface = Interface)
            else:
                if self.IPv6packet['NextHeader'] != None:
                    sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                          /self.IPv6packet['ExtHeader']
                          /self.IPv6packet['NextHeader'], iface = Interface)
                else:
                    sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                          /self.IPv6packet['ExtHeader'], iface = Interface)
        else:
            ## save
            if self.IPv6packet['ExtHeader'] == (None or ''):
                if self.IPv6packet['NextHeader'] != None:
                    wrpcap(File, (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['NextHeader']))
                else:
                    wrpcap(File, (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']))
            else:
                if self.IPv6packet['NextHeader'] != None:
                    wrpcap(File, (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader']/self.IPv6packet['NextHeader']))
                else:
                    wrpcap(File, (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader']))

        if Interface == None:
            self.sourcecode = self.sourcecode
        else:
            self.sourcecode = (self.sourcecode+
                               ', iface=\''+Interface+'\'')
        
        ## show sourcecode in info_msg:
        #print(self.sourcecode)
        self.sourcecode = ('sendp('+self.sourcecode+')')
        disp_sourcecode = QtGui.QMessageBox.information(None, "Scapy Quellcode", "Scapy Quellcode:\n\n%s" % self.sourcecode )


    ###############
    ## Build Extension Header

    def  BuildExtHdr(self, Num):

        ExtensionHeader = ''
        for d in range(Num-1):
            if self.ExtHdr[d][0] == 'Hop By Hop Options':
                self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrHopByHop()')
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrHopByHop()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrHopByHop()
            elif self.ExtHdr[d][0] == 'Destination Options':
                self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrDestOpt()')
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrDestOpt()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrDestOpt()
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
                if self.ExtHdr[d][2] == 0:
                    self.M_Flag = '0'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.ExtHdr[d][2],
                                                    id = int(self.ExtHdr[d][1]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 0,
                                                    id = int(self.ExtHdr[d][1]))
                else:
                    self.M_Flag = '1'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.ExtHdr[d][2],
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

    def BuildNextHeader(self):

        if self.tab4_comboBox.currentText() == 'ICMP':
            if self.tab4_Widget_radioButton.isChecked():
                NextHeader = self.BuildICMPv6_Ping()
            elif self.tab4_Widget_radioButton_2.isChecked():
                NextHeader = self.BuildICMPv6_RA()
            elif self.tab4_Widget_radioButton_3.isChecked():
                NextHeader = self.BuildICMPv6_PacketTooBig()
        elif self.tab4_comboBox.currentText() == 'TCP':
            NextHeader = self.BuildTCP()
        elif self.tab4_comboBox.currentText() == 'UDP':
            NextHeader = self.BuildUDP()
        elif self.tab4_comboBox.currentText() == 'No Next Header':
            NextHeader = self.BuildNoNextHeader()
        else:
            self.Fehler = QtGui.QMessageBox.information(None, '', 'Sorry this Next Header is not implemented yet.')

        return(NextHeader)

    ## Echo Request

    def BuildICMPv6_Ping(self):
        self.sourcecode = self.sourcecode+'/ICMPv6EchoRequest()'
        return(ICMPv6EchoRequest())

    ## Router Advertisement

    def BuildICMPv6_RA(self):
        ra=ICMPv6ND_RA(chlim=255, H=0L, M=0L, O=1L,
                       routerlifetime=1800, P=0L, retranstimer=0, prf=0L,
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
                               'routerlifetime=1800, P=0L, retranstimer=0, '+
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
                               'routerlifetime=1800, P=0L, retranstimer=0, '+
                               'prf=0L, res=0L)'+
                               '/ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, '+
                               'L=1L, len=4, '+
                               'prefix=\''+self.RAconf['Prefix']+'\', '+
                               'R=0L, validlifetime=1814400, '+
                               'prefixlen='+self.RAconf['Prefixlen']+', '+
                               'preferredlifetime=604800, type=3)')
            return(ra/prefix_info)

    ## Packet Too Big

    def BuildICMPv6_PacketTooBig(self):

        enMTU = self.tab4_Widget_lineEdit
        if enMTU.text() != '':
            MTU = enMTU.text()
        else:
            MTU = None
        q=ICMPv6PacketTooBig(mtu=int(MTU))
        self.sourcecode = self.sourcecode+'/ICMPv6PacketTooBig(mtu='+MTU+')'

        enPCAP = self.PayloadFile['Capture File']
        if enPCAP != '':
            path = enPCAP
            capture = rdpcap(str(path))
            enPCAPno = self.PayloadFile['Packet No.']
            if enPCAPno != '':
                no = int(enPCAPno)-1
            else:
                no = 0
            q = q/capture[no][IPv6]
            self.sourcecode = (self.sourcecode+'/rdpcap(\''+path+'\')['+
                               str(no)+'][IPv6]')
        return(q)

    ## TCP

    def BuildTCP(self):
        if self.tab4_Widget2_lineEdit.text() != '':
            SPort=int(self.tab4_Widget2_lineEdit.text())
        else:
            self.tab4_Widget2_lineEdit.setText('20')
            SPort=int(self.tab4_Widget2_lineEdit.text())
        if self.tab4_Widget2_lineEdit_2.text() != '':
            DPort=int(self.tab4_Widget2_lineEdit_2.text())
        else:
            self.tab4_Widget2_lineEdit_2.setText('80')
            DPort=int(self.tab4_Widget2_lineEdit_2.text())
        tcp= TCP(sport=SPort, dport=DPort)
        self.sourcecode = self.sourcecode+'/TCP(sport='+str(SPort)+' ,dport='+str(DPort)+')'
        if self.tab4_Widget2_radioButton_4.isChecked():
            return(tcp)
        elif self.tab4_Widget2_radioButton.isChecked():
            load = 'X'*int(self.tab4_Widget2_lineEdit_3.text())
            self.sourcecode = self.sourcecode+'/\'X\'*'+self.tab4_Widget2_lineEdit_3.text()
            return(tcp/load)
        elif self.tab4_Widget2_radioButton_2.isChecked():
            load = str(self.tab4_Widget2_lineEdit_4.text())
            self.sourcecode = self.sourcecode+'/\''+self.tab4_Widget2_lineEdit_4.text()+'\''
            return(tcp/load)
        elif self.tab4_Widget2_radioButton_3.isChecked():
            path = self.PayloadFile['Capture File']
            capture = rdpcap(str(path))
            PCAPno = self.PayloadFile['Packet No.']
            if PCAPno != '':
                no = int(PCAPno)-1
            else:
                no = 0
            load = capture[no][IPv6]
            self.sourcecode = (self.sourcecode+'/rdpcap(\''+path+'\')['+
                               str(no)+'][IPv6]')
            return(tcp/load)

    ## UDP

    def BuildUDP(self):
        if self.tab4_Widget3_lineEdit.text() != '':
            SPort=int(self.tab4_Widget3_lineEdit.text())
        else:
            self.tab4_Widget3_lineEdit.setText('53')
            SPort=int(self.tab4_Widget3_lineEdit.text())
        if self.tab4_Widget3_lineEdit_2.text() != '':
            DPort=int(self.tab4_Widget3_lineEdit_2.text())
        else:
            self.tab4_Widget3_lineEdit_2.setText('53')
            DPort=int(self.tab4_Widget3_lineEdit_2.text())
        udp= UDP(sport=SPort, dport=DPort)
        self.sourcecode = self.sourcecode+'/UDP(sport='+str(SPort)+' ,dport='+str(DPort)+')'
        if self.tab4_Widget3_radioButton_4.isChecked():
            return(udp)
        elif self.tab4_Widget3_radioButton.isChecked():
            load = 'X' * int(self.tab4_Widget3_lineEdit_3.text())
            self.sourcecode = self.sourcecode+'/\'X\'*'+self.tab4_Widget3_lineEdit_3.text()
            return(udp/load)
        elif self.tab4_Widget3_radioButton_2.isChecked():
            load = str(self.tab4_Widget3_lineEdit_4.text())
            self.sourcecode = self.sourcecode+'/\''+self.tab4_Widget3_lineEdit_4.text()+'\''
            return(udp/load)
        elif self.tab4_Widget3_radioButton_3.isChecked():
            path = self.PayloadFile['Capture File']
            capture = rdpcap(str(path))
            PCAPno = self.PayloadFile['Packet No.']
            if PCAPno != '':
                no = int(PCAPno)-1
            else:
                no = 0
            load = capture[no][IPv6]
            self.sourcecode = (self.sourcecode+'/rdpcap(\''+path+'\')['+
                               str(no)+'][IPv6]')
            return(udp/load)

    ## No Next Header

    def BuildNoNextHeader(self):
        self.sourcecode = self.sourcecode
        return(None)

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    m = Main()
    app.exec_()
