#!/usr/bin/python
# -*- coding:utf-8 -*-

#########################################################################
# Copyright/License Notice (New BSD License)                            #
#########################################################################
# Copyright (c) 2011, Beuth Hochschule fuer Technik Berlin              #
# All rights reserved.                                                  #
#                                                                       #
# Redistribution and use in source and binary forms, with or without    #
# modification, are permitted provided that the following conditions    #
# are met:                                                              #
#                                                                       #
#   * Redistributions of source code must retain the above copyright    #
#     notice, this list of conditions and the following disclaimer.     #
#                                                                       #
#   * Redistributions in binary form must reproduce the above copyright #
#     notice, this list of conditions and the following disclaimer in   #
#     the documentation and/or other materials provided with the        #
#     distribution.                                                     #
#                                                                       #
#                                                                       #
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS   #
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT     #
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR #
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT  #
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, #
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT      #
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, #
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY #
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT   #
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE #
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  #
#########################################################################


#########################################################################
##                                                                      #
## scapy-gui-ipv6 (A GUI for IPv6 Packetgeneration with Scapy)          #
##                                                                      #
#########################################################################
##                                                                      #
## Version: 1.3                                                         #
## Date:    31.03.2011                                                  #
##                                                                      #
#########################################################################

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
        self.Label.move(5, 5)
        self.ExtensionHdr = QtGui.QComboBox(self)
        self.ExtensionHdr.insertItem(0, 'Hop By Hop Options')
        self.ExtensionHdr.insertItem(1, 'Destination Options')
        self.ExtensionHdr.insertItem(2, 'Routing')
        self.ExtensionHdr.insertItem(3, 'Fragmentation')
        self.ExtensionHdr.setGeometry(QtCore.QRect(10, 30, 250, 31))

        ## Hop-By-Hop Header
        self.HopByHopHdr = QtGui.QWidget(self)
        self.HopByHopHdr.setGeometry(QtCore.QRect(0, 60, 360, 250))

        ## Destination Header
        self.DestinationHdr = QtGui.QWidget(self)
        self.DestinationHdr.setGeometry(QtCore.QRect(0, 60, 360, 250))
        
        ## Routing Header Type 0
        self.RoutingHdr = QtGui.QWidget(self)
        self.RoutingHdr.setGeometry(QtCore.QRect(0, 60, 360, 250))
        self.RoutingHdr_Label = QtGui.QLabel("Routing Hop addresses:", self.RoutingHdr)
        self.RoutingHdr_Label.move(5, 10)
        self.RoutingHdr_AddrArray = QtGui.QTableWidget(0, 1, self.RoutingHdr)
        self.RoutingHdr_AddrArray.setHorizontalHeaderLabels(["Routing Hop"])
        self.RoutingHdr_AddrArray.setColumnWidth(0,200)
        self.RoutingHdr_AddrArray.setGeometry(QtCore.QRect(10, 40, 250, 150))
        self.RoutingHdr_Address = QtGui.QLineEdit(self.RoutingHdr)
        self.RoutingHdr_Address.setGeometry(QtCore.QRect(10, 200, 250, 31))
        self.RoutingHdr_AddButton = QtGui.QPushButton("Add",self.RoutingHdr)
        self.RoutingHdr_AddButton.move(270, 200)
        self.RoutingHdr_DeleteButton = QtGui.QPushButton("Delete",self.RoutingHdr)
        self.RoutingHdr_DeleteButton.move(270, 165)
        self.connect(self.RoutingHdr_AddButton, QtCore.SIGNAL('clicked()'), self.AddIP)
        self.connect(self.RoutingHdr_DeleteButton, QtCore.SIGNAL('clicked()'), self.DeleteIP)

        ## Fragment Header
        self.FragmentHdr = QtGui.QWidget(self)
        self.FragmentHdr.setGeometry(QtCore.QRect(0, 60, 360, 250))
        self.FragmentHdr_Label = QtGui.QLabel("Fragment Offset:", self.FragmentHdr)
        self.FragmentHdr_Label.move(5, 10)
        self.FragmentHdr_FragOffset = QtGui.QLineEdit('0', self.FragmentHdr)
        self.FragmentHdr_FragOffset.setGeometry(QtCore.QRect(10, 35, 300, 31))
        self.FragmentHdr_Label_2 = QtGui.QLabel("Identification:", self.FragmentHdr)
        self.FragmentHdr_Label_2.move(5, 80)
        self.FragmentHdr_ID = QtGui.QLineEdit('0', self.FragmentHdr)
        self.FragmentHdr_ID.setGeometry(QtCore.QRect(10, 105, 300, 30))
        self.FragmentHdr_M = QtGui.QCheckBox("Last Package", self.FragmentHdr)
        self.FragmentHdr_M.move(10, 160)
        
        self.HopByHopHdr.setVisible(False)
        self.DestinationHdr.setVisible(False)
        self.RoutingHdr.setVisible(False)
        self.FragmentHdr.setVisible(False)

        if self.ExtHdr[0] == '':
            self.HopByHopHdr.setVisible(True)
        elif self.ExtHdr[0] == 'Hop By Hop Options':
            self.ExtensionHdr.setCurrentIndex(0)
            self.HopByHopHdr.setVisible(True)

        elif self.ExtHdr[0] == 'Destination Options':
            self.ExtensionHdr.setCurrentIndex(1)
            self.DestinationHdr.setVisible(True)

        elif self.ExtHdr[0] == 'Routing':
            self.ExtensionHdr.setCurrentIndex(2)
            self.RoutingHdr.setVisible(True)
            i = len(self.ExtHdr[1])
            for d in range(i):
                self.RoutingHdr_AddrArray.insertRow(d)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[1][d])
                self.RoutingHdr_AddrArray.setItem(d, 0, t1)
        elif self.ExtHdr[0] == 'Fragmentation':
            self.ExtensionHdr.setCurrentIndex(3)
            self.FragmentHdr.setVisible(True)
            self.FragmentHdr_FragOffset.setText(str(self.ExtHdr[1]))
            self.FragmentHdr_ID.setText(str(self.ExtHdr[2]))
            if self.ExtHdr[3] == 0:
                self.FragmentHdr_M.setChecked(True)
             

        self.connect(self.ExtensionHdr, QtCore.SIGNAL('activated(int)'), self.EHConf)
        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(111, 300, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        self.show()
 
    def EHConf(self):
        if self.ExtensionHdr.currentText() == 'Hop By Hop Options':
            self.HopByHopHdr.setVisible(True)
            self.DestinationHdr.setVisible(False)
            self.RoutingHdr.setVisible(False)
            self.FragmentHdr.setVisible(False)
        elif self.ExtensionHdr.currentText() == 'Destination Options':
            self.HopByHopHdr.setVisible(False)
            self.DestinationHdr.setVisible(True)
            self.RoutingHdr.setVisible(False)
            self.FragmentHdr.setVisible(False)
        elif self.ExtensionHdr.currentText() == 'Routing':
            self.HopByHopHdr.setVisible(False)
            self.DestinationHdr.setVisible(False)
            self.RoutingHdr.setVisible(True)
            self.FragmentHdr.setVisible(False)
        elif self.ExtensionHdr.currentText() == 'Fragmentation':
            self.HopByHopHdr.setVisible(False)
            self.DestinationHdr.setVisible(False)
            self.RoutingHdr.setVisible(False)
            self.FragmentHdr.setVisible(True)


    def AddIP(self):
        numRows = self.RoutingHdr_AddrArray.rowCount()
        if numRows < 16:
            self.RoutingHdr_AddrArray.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.RoutingHdr_Address.text())
            self.RoutingHdr_AddrArray.setItem(numRows, 0, t1)
        else:
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")

    def DeleteIP(self):
        Row = self.RoutingHdr_AddrArray.currentRow()
        if Row >= 0:
            self.RoutingHdr_AddrArray.removeRow(Row)

    def fertig(self):
        self.ExtHdr[0] = self.ExtensionHdr.currentText()
        self.addresses=[]
            
        if self.ExtHdr[0] == 'Routing':
            i = self.RoutingHdr_AddrArray.rowCount()
            if i > 0:
                for d in range(i):
                    self.addresses.append([])
                    self.addresses[d] = str(QtGui.QTableWidgetItem.text(self.RoutingHdr_AddrArray.item(d, 0)))
                self.ExtHdr[1] = self.addresses
            else:
                self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Min one addresse is requiered!")
        elif self.ExtHdr[0] == 'Fragmentation':
            if self.FragmentHdr_FragOffset.text() == '':
                self.FragmentHdr_FragOffset.setText('0')
            if self.FragmentHdr_ID.text() == '':
                self.FragmentHdr_ID.setText('0')
            self.ExtHdr[1] = int(self.FragmentHdr_FragOffset.text())
            self.ExtHdr[2] = int(self.FragmentHdr_ID.text())
            if self.FragmentHdr_M.isChecked() == True:
                self.ExtHdr[3] = 0
            else:
                self.ExtHdr[3] = 1
        self.accept()

class RA(QtGui.QDialog):
    """Router Advertisement"""
    def __init__(self,RAconf):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Router Advertisement")
        self.resize(320, 300)
        self.RAconf = RAconf
        self.Label = QtGui.QLabel("Prefix:", self)
        self.Label.move(5, 15)
        self.Label_2 = QtGui.QLabel("Prefix lenght:", self)
        self.Label_2.move(5, 85)
        self.line = QtGui.QFrame(self)
        self.line.setGeometry(QtCore.QRect(5, 150, 310, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.Label_3 = QtGui.QLabel("optional:", self)
        self.Label_3.move(125, 160)
        self.Label_4 = QtGui.QLabel("ICMPv6 Option (Source Link-Layer-Address):", self)
        self.Label_4.move(5, 190)
        self.Prefix = QtGui.QLineEdit(self)
        self.Prefix.setGeometry(QtCore.QRect(10, 40, 300, 30))
        self.Prefix.setText(self.RAconf['Prefix'])
        self.PrefixLen = QtGui.QLineEdit(self)
        self.PrefixLen.setGeometry(QtCore.QRect(10, 110, 60, 30)) 
        self.PrefixLen.setText(self.RAconf['Prefixlen'])
        self.LLSourceAddr = QtGui.QComboBox(self)
        self.LLSourceAddr.setGeometry(QtCore.QRect(10, 215, 300, 30))
        self.LLSourceAddr.setEditable(True)

        ## init cbSrcLLaddr
        iflist = get_if_list()
        i = len(iflist)
        self.LLSourceAddr.insertItem(0, '')
        for d in range(0, i):
            self.LLSourceAddr.addItem(get_if_hwaddr(iflist[d]))
        self.LLSourceAddr.setEditText(self.RAconf['SourceLL'])

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(111, 260, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        self.show()
 
    def fertig(self):
        if ((self.Prefix.text() == '') or 
            (self.PrefixLen.text() == '')):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Prefix and Prefix length are requiered!\n(Default: Prefix = 'fd00:141:64:1::'; Prefixlength = 64)")
        if self.Prefix.text() == '':
            self.Prefix.setText('fd00:141:64:1::')
        if self.PrefixLen.text() == '':
            self.PrefixLen.setText('64')
        self.RAconf['Prefix'] = self.Prefix.text()
        self.RAconf['Prefixlen'] = self.PrefixLen.text()
        self.RAconf['SourceLL'] = self.LLSourceAddr.currentText()        
        self.accept()

class Payload(QtGui.QDialog):
    """Load Pcap Data"""
    def __init__(self,PayloadFile):
        QtGui.QDialog.__init__(self)

        self.setWindowTitle("Payload")
        self.resize(420, 200)
        self.PayloadFile = PayloadFile

        self.Label = QtGui.QLabel("Define a packet which will be used as payload.", self)
        self.Label.setGeometry(QtCore.QRect(5, 0, 320, 30))
        self.Label_2 = QtGui.QLabel("Capture File:", self)
        self.Label_2.move(5, 50)
        self.Label_3 = QtGui.QLabel("Packet No.:", self)
        self.Label_3.move(5, 110)
        self.PacketFile = QtGui.QLineEdit(self.PayloadFile['Capture File'], self)
        self.PacketFile.setGeometry(QtCore.QRect(10, 70, 301, 27))
        self.PacketNo = QtGui.QLineEdit(self.PayloadFile['Packet No.'], self)
        self.PacketNo.setGeometry(QtCore.QRect(10, 130, 113, 27))
        self.pushButton = QtGui.QPushButton("Search...", self)
        self.pushButton.move(310, 70)
        self.connect(self.pushButton, QtCore.SIGNAL('clicked(bool)'), self.ask_for_filename)

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(161, 160, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        
        self.show()

    def ask_for_filename(self):
        self.fileDialog = QtGui.QFileDialog.getOpenFileName(self,"FileDialog")
	self.PacketFile.setText(self.fileDialog)
 
    def fertig(self):
        self.PayloadFile['Capture File'] = self.PacketFile.text()
        self.PayloadFile['Packet No.'] = self.PacketNo.text()
        
        self.accept()

class Main(QtGui.QMainWindow):

    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        self.setWindowTitle("Scapy GUI")
        self.resize(600, 370)
        self.makeActions()
        self.makeMenu()

        self.EthH = {'LLSourceAddr':None,'LLDstAddr':None}
        self.IPH = {'Dst':None,'SourceIP':None,'NextHeader':None}
        self.RAconf = {'Prefix':'fd00:141:64:1::','Prefixlen':'64','SourceLL':''}
        self.IPv6packet = {'EthHeader':None,'IPHeader':None,
                           'ExtHeader':None,'NextHeader':None}

        self.ExtHdr = [['','','','']]
        self.PayloadFile = {'Capture File':'','Packet No.':'1'}
        self.sourcecode = None ## var to display the sourcecode 

        # TabWidget
        self.tabWidget = QtGui.QTabWidget(self)
        self.tabWidget.setGeometry(QtCore.QRect(0, 30, 600, 300))

	    # First Tab - Ethernet Header
        self.tab_EthH = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_EthH, "Ethernet Header (optional)")
        self.tab_EthernetHdr_Label = QtGui.QLabel("All fields are optional.", self.tab_EthH)
        self.tab_EthernetHdr_Label.move(5, 0)
        self.tab_EthernetHdr_Label_2 = QtGui.QLabel("Interface:", self.tab_EthH)
        self.tab_EthernetHdr_Label_2.move(5, 35)
        self.tab_EthernetHdr_Label_3 = QtGui.QLabel("Destination Link Layer Address:", self.tab_EthH)
        self.tab_EthernetHdr_Label_3.move(5, 105)
        self.tab_EthernetHdr_Label_4 = QtGui.QLabel("Source Link Layer Address:", self.tab_EthH)
        self.tab_EthernetHdr_Label_4.move(5, 175)
        self.Interface = QtGui.QComboBox(self.tab_EthH)
        self.Interface.setGeometry(QtCore.QRect(10, 60, 300, 31))
        self.LLDstAddr = QtGui.QLineEdit(self.tab_EthH)
        self.LLDstAddr.setGeometry(QtCore.QRect(10, 130, 300, 31))
        self.LLSrcAddr = QtGui.QComboBox(self.tab_EthH)
        self.LLSrcAddr.setGeometry(QtCore.QRect(10, 200, 300, 31))
        self.LLSrcAddr.setEditable(True)

        # Second Tab - IPv6 Header
        self.tab_IPv6 = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_IPv6, "IPv6 Header")
        self.tab_IPv6_Label = QtGui.QLabel("Destination IPv6-address (or name):", self.tab_IPv6)
        self.tab_IPv6_Label.move(5, 35)
        self.tab_IPv6_Label_2 = QtGui.QLabel("Source IPv6-address:", self.tab_IPv6)
        self.tab_IPv6_Label_2.move(5, 105)
        self.IPv6_DstAddr = QtGui.QComboBox(self.tab_IPv6)
        self.IPv6_DstAddr.setGeometry(QtCore.QRect(10, 60, 300, 31))
        self.IPv6_DstAddr.setEditable(True)
        self.IPv6_DstAddr.addItem('')
        # add some well known addresses to the the drop-down list
        self.IPv6_DstAddr.addItem('ff01::1')
        self.IPv6_DstAddr.addItem('ff02::1')
        self.IPv6_DstAddr.addItem('ff80::1')
        #self.IPv6_DstAddr.addItem('2001:0db8:85a3:08d3::1')
        self.IPv6_SrcAddr = QtGui.QComboBox(self.tab_IPv6)
        self.IPv6_SrcAddr.setGeometry(QtCore.QRect(10, 130, 300, 31))
        self.IPv6_SrcAddr.setEditable(True)
        self.IPv6_SrcAddr.addItem('')
        self.IPv6_SrcAddr.addItem('ff01::1')
        self.IPv6_SrcAddr.addItem('ff02::1')

        # Third Tab - Extension Header
        self.tab_ExtHdr = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_ExtHdr, "Extension Header")
        self.ExtHdr_tableWidget = QtGui.QTableWidget(0, 1, self.tab_ExtHdr)
        self.ExtHdr_tableWidget.setHorizontalHeaderLabels(["Extension Header"])
        self.ExtHdr_tableWidget.setColumnWidth(0,230)
        self.ExtHdr_tableWidget.setGeometry(QtCore.QRect(130, 10, 250, 250))
        self.ExtHdr_AddButton = QtGui.QPushButton("Add", self.tab_ExtHdr)
        self.ExtHdr_AddButton.move(420, 50)
        self.ExtHdr_EditButton = QtGui.QPushButton("Edit", self.tab_ExtHdr)
        self.ExtHdr_EditButton.move(420, 80)
        self.ExtHdr_DeleteButton = QtGui.QPushButton("Delete", self.tab_ExtHdr)
        self.ExtHdr_DeleteButton.move(420, 110)
        self.connect(self.ExtHdr_AddButton, QtCore.SIGNAL('clicked(bool)'), self.slotAddExtHdr)
        self.connect(self.ExtHdr_EditButton, QtCore.SIGNAL('clicked(bool)'), self.slotEditExtHdr)
        self.connect(self.ExtHdr_DeleteButton, QtCore.SIGNAL('clicked(bool)'), self.slotDeleteExtHdr)

        # Forth Tab - Next Header
        self.tab_NextHeader = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_NextHeader, "Next Header")
        self.NextHeader_Type = QtGui.QComboBox(self.tab_NextHeader)
        self.NextHeader_Type.insertItem(0, 'ICMP')
        self.NextHeader_Type.insertItem(1, 'TCP')
        self.NextHeader_Type.insertItem(2, 'UDP')
        self.NextHeader_Type.insertItem(3, 'No Next Header')
        self.NextHeader_Type.move(10, 20)
            # ICMP Typ
        self.NH_ICMP = QtGui.QWidget(self.tab_NextHeader)
        self.NH_ICMP.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.NH_ICMP_Ping = QtGui.QRadioButton("Ping", self.NH_ICMP)
        self.NH_ICMP_Ping.move(30, 30)
        self.NH_ICMP_Ping.setChecked(True)
        self.NH_ICMP_RouterAd = QtGui.QRadioButton("Router Advertisement", self.NH_ICMP)
        self.NH_ICMP_RouterAd.move(30, 70)
        self.connect(self.NH_ICMP_RouterAd, QtCore.SIGNAL('clicked(bool)'), self.slotRouterAdvertisement)
        self.NH_ICMP_PacketTooBig = QtGui.QRadioButton("Packet Too Big", self.NH_ICMP)
        self.NH_ICMP_PacketTooBig.move(30, 110)
        self.connect(self.NH_ICMP_PacketTooBig, QtCore.SIGNAL('clicked(bool)'), self.slotPacket_Too_Big)
        self.NH_ICMP_Label = QtGui.QLabel("MTU:", self.NH_ICMP)
        self.NH_ICMP_Label.move(80, 140)
        self.NH_ICMP_MTU = QtGui.QLineEdit("1280", self.NH_ICMP)
        self.NH_ICMP_MTU.setGeometry(QtCore.QRect(120, 136, 61, 25))
            # TCP
        self.NH_TCP = QtGui.QWidget(self.tab_NextHeader)
        self.NH_TCP.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.NH_TCP.setVisible(False)
        self.NH_TCP_Label = QtGui.QLabel("Source Port:", self.NH_TCP)
        self.NH_TCP_Label.move(30, 30)
        self.NH_TCP_SrcPort = QtGui.QLineEdit("20", self.NH_TCP)
        self.NH_TCP_SrcPort.setGeometry(QtCore.QRect(150, 26, 60, 25))
        self.NH_TCP_Label_2 = QtGui.QLabel("Destination Port:", self.NH_TCP)
        self.NH_TCP_Label_2.move(30, 70)
        self.NH_TCP_DstPort = QtGui.QLineEdit("80", self.NH_TCP)
        self.NH_TCP_DstPort.setGeometry(QtCore.QRect(150, 66, 60, 25))
        self.NH_TCP_Label_3 = QtGui.QLabel("Flags:", self.NH_TCP)
        self.NH_TCP_Label_3.move(30, 120)
        self.NH_TCP_Flag_URG = QtGui.QRadioButton("URG", self.NH_TCP)
        self.NH_TCP_Flag_URG.setAutoExclusive(False)
        self.NH_TCP_Flag_URG.move(50, 140)
        self.NH_TCP_Flag_ACK = QtGui.QRadioButton("ACK", self.NH_TCP)
        self.NH_TCP_Flag_ACK.setAutoExclusive(False)
        self.NH_TCP_Flag_ACK.move(50, 160)
        self.NH_TCP_Flag_PSH = QtGui.QRadioButton("PSH", self.NH_TCP)
        self.NH_TCP_Flag_PSH.setAutoExclusive(False)
        self.NH_TCP_Flag_PSH.move(110, 140)
        self.NH_TCP_Flag_RST = QtGui.QRadioButton("RST", self.NH_TCP)
        self.NH_TCP_Flag_RST.setAutoExclusive(False)
        self.NH_TCP_Flag_RST.move(110, 160)
        self.NH_TCP_Flag_SYN = QtGui.QRadioButton("SYN", self.NH_TCP)
        self.NH_TCP_Flag_SYN.setAutoExclusive(False)
        self.NH_TCP_Flag_SYN.move(170, 140)
        self.NH_TCP_Flag_SYN.setChecked(True)
        self.NH_TCP_Flag_FIN = QtGui.QRadioButton("FIN", self.NH_TCP)
        self.NH_TCP_Flag_FIN.setAutoExclusive(False)
        self.NH_TCP_Flag_FIN.move(170, 160)

        # TCP Payload
        self.NH_TCP_Payload = QtGui.QWidget(self.NH_TCP) 
        self.NH_TCP_Payload.setGeometry(QtCore.QRect(300, 0, 300, 200))
        self.NH_TCP_Payload_Label = QtGui.QLabel("Payload:", self.NH_TCP_Payload)
        self.NH_TCP_Payload_XLength = QtGui.QRadioButton("String with 'X' * Length", self.NH_TCP_Payload)
        self.NH_TCP_Payload_XLength.move(30, 30)
        self.NH_TCP_Payload_XLength.setChecked(True)
        self.NH_TCP_Payload_Label_2 = QtGui.QLabel("Length:", self.NH_TCP_Payload)
        self.NH_TCP_Payload_Label_2.move(57, 60)
        self.NH_TCP_Payload_Length = QtGui.QLineEdit("1", self.NH_TCP_Payload)
        self.NH_TCP_Payload_Length.setGeometry(QtCore.QRect(120, 56, 60, 25))
        self.NH_TCP_Payload_PayString = QtGui.QRadioButton("String:", self.NH_TCP_Payload)
        self.NH_TCP_Payload_PayString.move(30, 90)
        self.NH_TCP_Payload_String = QtGui.QLineEdit("X", self.NH_TCP_Payload)
        self.NH_TCP_Payload_String.setGeometry(QtCore.QRect(120, 88, 60, 25))
        self.NH_TCP_Payload_PcapFile = QtGui.QRadioButton("pcap File", self.NH_TCP_Payload)
        self.NH_TCP_Payload_PcapFile.move(30, 130)
        self.connect(self.NH_TCP_Payload_PcapFile, QtCore.SIGNAL('clicked(bool)'), self.slotPayloadTCP)
        self.NH_TCP_Payload_NoPayload = QtGui.QRadioButton("No Payload", self.NH_TCP_Payload)
        self.NH_TCP_Payload_NoPayload.move(30, 170)
        # UDP
        self.NH_UDP = QtGui.QWidget(self.tab_NextHeader)
        self.NH_UDP.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.NH_UDP.setVisible(False)
        self.NH_UDP_Label = QtGui.QLabel("Source Port:", self.NH_UDP)
        self.NH_UDP_Label.move(30, 30)
        self.NH_UDP_SrcPort = QtGui.QLineEdit("53", self.NH_UDP)
        self.NH_UDP_SrcPort.setGeometry(QtCore.QRect(150, 26, 60, 25))
        self.NH_UDP_Label_2 = QtGui.QLabel("Destination Port:", self.NH_UDP)
        self.NH_UDP_Label_2.move(30, 70)
        self.NH_UDP_DstPort = QtGui.QLineEdit("53", self.NH_UDP)
        self.NH_UDP_DstPort.setGeometry(QtCore.QRect(150, 66, 60, 25))
        # UDP Payload
        self.NH_UDP_Payload = QtGui.QWidget(self.NH_UDP) 
        self.NH_UDP_Payload.setGeometry(QtCore.QRect(300, 0, 300, 200))
        self.NH_UDP_Label = QtGui.QLabel("Payload:", self.NH_UDP_Payload)
        self.NH_UDP_Payload_XLength = QtGui.QRadioButton("String with 'X' * Length", self.NH_UDP_Payload)
        self.NH_UDP_Payload_XLength.move(30, 30)
        self.NH_UDP_Payload_XLength.setChecked(True)
        self.NH_UDP_Label_2 = QtGui.QLabel("Length:", self.NH_UDP_Payload)
        self.NH_UDP_Label_2.move(57, 60)
        self.NH_UDP_Payload_Length = QtGui.QLineEdit("1", self.NH_UDP_Payload)
        self.NH_UDP_Payload_Length.setGeometry(QtCore.QRect(120, 56, 60, 25))
        self.NH_UDP_Payload_PayString = QtGui.QRadioButton("String:", self.NH_UDP_Payload)
        self.NH_UDP_Payload_PayString.move(30, 90)
        self.NH_UDP_Payload_String = QtGui.QLineEdit("X", self.NH_UDP_Payload)
        self.NH_UDP_Payload_String.setGeometry(QtCore.QRect(120, 88, 60, 25))
        self.NH_UDP_Payload_PcapFile = QtGui.QRadioButton("pcap File", self.NH_UDP_Payload)
        self.NH_UDP_Payload_PcapFile.move(30, 130)
        self.connect(self.NH_UDP_Payload_PcapFile, QtCore.SIGNAL('clicked(bool)'), self.slotPayloadUDP)
        self.NH_UDP_Payload_NoPayload = QtGui.QRadioButton("No Payload", self.NH_UDP_Payload)
        self.NH_UDP_Payload_NoPayload.move(30, 170)
        # no Next Header
        self.NH_NoNextHdr = QtGui.QWidget(self.tab_NextHeader)
        self.NH_NoNextHdr.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.NH_NoNextHdr.setVisible(False)
        self.connect(self.NextHeader_Type, QtCore.SIGNAL('activated(int)'), self.NHConf)

        # Send Button
        self.SendButton = QtGui.QPushButton("Send", self)
        self.SendButton.move(190, 335)
        self.connect(self.SendButton, QtCore.SIGNAL('clicked(bool)'), self.slotSend)        

        # Clipboard Button
        self.ClipboardButton = QtGui.QPushButton("Clipboard", self)
        self.ClipboardButton.move(310, 335)
        self.connect(self.ClipboardButton, QtCore.SIGNAL('clicked(bool)'), self.slotClipboard)

        self.show()

        ## get Interfaces, add them to the drop-down list
        iflist = get_if_list()
        i = 0
        self.Interface.insertItem(0, '')
        for d in iflist:
            self.Interface.addItem(d)

        ## get SourceLinkLayerAddresses, add them to the drop-down list
        i = len(iflist)
        self.LLSrcAddr.insertItem(0, '')
        for d in range(0, i):
            self.LLSrcAddr.addItem(get_if_hwaddr(iflist[d]))

        ## get IPv6 Addresses, add them to the drop-down list
        ipv6 = read_routes6()
        length_ipv6 = len(ipv6)
        for d in range(0, length_ipv6):
            if ipv6[d][3] == 'lo':
                self.IPv6_SrcAddr.addItem(str(ipv6[d][0]))
                self.IPv6_DstAddr.addItem(str(ipv6[d][0]))
        for d in range(0, length_ipv6):
            if ipv6[d][2] != '::':
                self.IPv6_DstAddr.addItem(str(ipv6[d][2]))
        for d in range(0, length_ipv6):
            if ipv6[d][1] != 0 and ipv6[d][1] != 128 and ipv6[d][0] != 'fe80::':
                self.IPv6_DstAddr.addItem(str(ipv6[d][0])+'1')

    def NHConf(self):
        if self.NextHeader_Type.currentText() == 'ICMP':
            self.NH_ICMP.setVisible(True)
            self.NH_TCP.setVisible(False)
            self.NH_UDP.setVisible(False)
            self.NH_NoNextHdr.setVisible(False)
        elif self.NextHeader_Type.currentText() == 'TCP':
            self.NH_ICMP.setVisible(False)
            self.NH_TCP.setVisible(True)
            self.NH_UDP.setVisible(False)
            self.NH_NoNextHdr.setVisible(False)
        elif self.NextHeader_Type.currentText() == 'UDP':
            self.NH_ICMP.setVisible(False)
            self.NH_TCP.setVisible(False)
            self.NH_UDP.setVisible(True)
            self.NH_NoNextHdr.setVisible(False)
        elif self.NextHeader_Type.currentText() == 'No Next Header':
            self.NH_ICMP.setVisible(False)
            self.NH_TCP.setVisible(False)
            self.NH_UDP.setVisible(False)
            self.NH_NoNextHdr.setVisible(True)

    def makeActions(self):
        self._saveAction = QtGui.QAction("&Save", None)
        self._loadAction = QtGui.QAction("&Load", None)
        self._exitAction = QtGui.QAction("&Exit", None)
        self.connect(self._saveAction, QtCore.SIGNAL('triggered()'), self.slotSave)
        self.connect(self._loadAction, QtCore.SIGNAL('triggered()'), self.slotLoad)
        self.connect(self._exitAction, QtCore.SIGNAL('triggered()'), self.slotClose)

    def makeMenu(self):
        menuBar = self.menuBar()
        fileMenu = menuBar.addMenu("&File")
        fileMenu.addAction(self._saveAction)
        fileMenu.addAction(self._loadAction)
        fileMenu.addAction(self._exitAction)

    def slotAddExtHdr(self):
        """Ruft die Einstellung der Extension Header auf"""
        self.setEnabled(False)
        Rows = len(self.ExtHdr)
        eh = EH(self.ExtHdr[Rows-1])
        eh.exec_()
        if self.ExtHdr[Rows-1][0] != '':
            numRows = self.ExtHdr_tableWidget.rowCount()
            self.ExtHdr_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.ExtHdr[Rows-1][0])
            self.ExtHdr_tableWidget.setItem(numRows, 0, t1)
            item = self.ExtHdr_tableWidget.item(numRows, 0)
            item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
            item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
            self.ExtHdr.append(['','','',''])
        self.setEnabled(True)

    def slotEditExtHdr(self):
        Row = self.ExtHdr_tableWidget.currentRow()
        if Row != -1:
            self.setEnabled(False)
            eh = EH(self.ExtHdr[Row])
            eh.exec_()
            t1 = QtGui.QTableWidgetItem(self.ExtHdr[Row][0])
            self.ExtHdr_tableWidget.setItem(Row, 0, t1)
            item = self.ExtHdr_tableWidget.item(Row, 0)
            item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
            item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
            self.setEnabled(True)

    def slotDeleteExtHdr(self):
        """Löscht den markierten Extension Header"""
        Row = self.ExtHdr_tableWidget.currentRow()
        if Row >= 0:
            self.ExtHdr_tableWidget.removeRow(Row)
            del self.ExtHdr[Row]
            self.ExtHdr_tableWidget.setCurrentCell(Row,0)

    def slotRouterAdvertisement(self):
        """Ruft die Router Advertisement auf"""
        self.setEnabled(False)
        ra = RA(self.RAconf)
        ra.exec_()
        self.setEnabled(True)

    def slotPacket_Too_Big(self):
        """Ruft die Paylaod Einstellungen auf"""
        self.setEnabled(False)
        payload = Payload(self.PayloadFile)
        payload.exec_()
        if ((self.PayloadFile['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
            self.NH_ICMP_Ping.setChecked(True)
        self.setEnabled(True)

    def slotPayloadTCP(self):
        """Ruft die Paylaod Einstellungen auf"""
        self.setEnabled(False)
        payload = Payload(self.PayloadFile)
        payload.exec_()
        if ((self.PayloadFile['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
            self.NH_TCP_Payload_XLength.setChecked(True)
        self.setEnabled(True)

    def slotPayloadUDP(self):
        """Ruft die Paylaod Einstellungen auf"""
        self.setEnabled(False)
        payload = Payload(self.PayloadFile)
        payload.exec_()
        if ((self.PayloadFile['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
            self.NH_UDP_Payload_XLength.setChecked(True)
        self.setEnabled(True)

    def slotSave(self):
        """Wird aufgerufen, um alle eingestellten Daten zu speichern."""
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "",("pcap(*.pcap)"))
        if filename != '':
            if filename.endsWith('.pcap') == False:
                filename=(filename+'.pcap')
            self.Buildit(1,filename)

    def slotLoad(self):
        """Wird aufgerufen, um früher eingestellten Daten zu laden."""
        filename = QtGui.QFileDialog.getOpenFileName(self,"Load File", "",("pcap(*.pcap)"))
        Packet = rdpcap(str(filename))
        Data = Packet[0]
        self.LLDstAddr.setText(Data[0].dst)
        self.LLSrcAddr.setEditText(Data[0].src)
        self.IPv6_DstAddr.setEditText(Data[1].dst)
        self.IPv6_SrcAddr.setEditText(Data[1].src)
        Data = Data[1]
        self.NextHeader = Data.nh
        Data = Data[1]
        for d in range(self.ExtHdr_tableWidget.rowCount()):
            self.ExtHdr_tableWidget.removeRow(0)
        self.ExtHdr = [['','','','']]
        d = 0
        temp = 0
        count = 0
        while count < 1:
            if self.NextHeader == 0:
                temp = Data.nh
                self.ExtHdr[d][0] = 'Hop By Hop Options'
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.ExtHdr_tableWidget.setItem(numRows, 0, t1)
                item = self.ExtHdr_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled)
                item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
                self.ExtHdr.append(['','','',''])
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
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.ExtHdr_tableWidget.setItem(numRows, 0, t1)
                item = self.ExtHdr_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled)
                item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
                self.ExtHdr.append(['','','',''])
                d = d + 1
                count = 0
                Data = Data[1]
            elif self.NextHeader == 44:
                temp = Data.nh
                self.ExtHdr[d][0] = 'Fragmentation'
                self.ExtHdr[d][1] = Data.offset
                self.ExtHdr[d][2] = Data.id
                self.ExtHdr[d][3] = Data.m
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.ExtHdr_tableWidget.setItem(numRows, 0, t1)
                item = self.ExtHdr_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled)
                item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
                self.ExtHdr.append(['','','',''])
                d = d + 1
                count = 0
                Data = Data[1]
            elif self.NextHeader == 60:
                temp = Data.nh
                self.ExtHdr[d][0] = 'Destination Options'
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.ExtHdr[d][0])
                self.ExtHdr_tableWidget.setItem(numRows, 0, t1)
                item = self.ExtHdr_tableWidget.item(numRows, 0)
                item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled)
                item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
                self.ExtHdr.append(['','','',''])
                d = d + 1
                if len(Data) == Data.len + 8:
                    count = 1
                else:
                    count = 0
                Data = Data[2]
            elif self.NextHeader == 58:
                self.NextHeader_Type.setCurrentIndex(0)
                self.NHConf()
                if Data.type == 128:
                    self.NH_ICMP_Ping.setChecked(True)
                elif Data.type == 134:
                    self.NH_ICMP_RouterAd.setChecked(True)
                    self.RAconf['Prefix'] = Data.prefix
                    self.RAconf['Prefixlen'] = Data.prefixlen
                elif Data.type == 2:
                    self.NH_ICMP_PacketTooBig.setChecked(True)
                count = 1
            elif self.NextHeader == 6:
                self.NextHeader_Type.setCurrentIndex(1)
                self.NHConf()
                self.NH_TCP_SrcPort.setText(str(Data.sport))
                self.NH_TCP_DstPort.setText(str(Data.dport))
                x = bin(Data.flags)
                Flags = [False, False, False, False, False, False]
                count2 = len(x)
                while count2 >=3:
                    if x[count2-1] == '1':
                        Flags[5-(len(x)-count2)] = True
                    count2 = count2-1
                self.NH_TCP_Flag_URG.setChecked(Flags[0])
                self.NH_TCP_Flag_ACK.setChecked(Flags[1])
                self.NH_TCP_Flag_PSH.setChecked(Flags[2])
                self.NH_TCP_Flag_RST.setChecked(Flags[3])
                self.NH_TCP_Flag_SYN.setChecked(Flags[4])
                self.NH_TCP_Flag_FIN.setChecked(Flags[5])
                
                count = 1
            elif self.NextHeader == 17:
                self.NextHeader_Type.setCurrentIndex(2)
                self.NHConf()
                self.NH_UDP_SrcPort.setText(str(Data.sport))
                self.NH_UDP_DstPort.setText(str(Data.dport))
                count = 1
            elif self.NextHeader == 59:
                self.NextHeader_Type.setCurrentIndex(3)
                self.NHConf()
                count = 1
            else:
                count = 1
            self.NextHeader = temp

    def slotSend(self):
        self.Buildit(0,'')

    def slotClipboard(self):
        self.Buildit(2,'')

    def slotClose(self):
        """Wird aufgerufen, wenn das Fenster geschlossen wird"""
        ret = QtGui.QMessageBox.question(None, "Quit?", "You want to close this program?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if ret == QtGui.QMessageBox.Yes:
            self.close()


###################
## build ip packets

    def Buildit(self,Type,File):

        ##################
        ## Ethernet Header

        enDstLLaddr = self.LLDstAddr

        if enDstLLaddr.text() != '':
            self.EthH['LLDstAddr'] = str(enDstLLaddr.text())
        else:
            self.EthH['LLDstAddr'] = None

        cbSrcLLaddr = self.LLSrcAddr

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

        enDstIP =  self.IPv6_DstAddr
        if enDstIP.currentText() != '':
            self.IPH['Dst'] = str(enDstIP.currentText())
        else:
            self.IPH['Dst'] = None
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Destination Address is requiered\nto create a valid package!")

        enSourceIP =  self.IPv6_SrcAddr
        if enSourceIP.currentText() != '':
            self.IPH['SourceIP'] = str(enSourceIP.currentText())
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

        cbIface =  self.Interface
        if cbIface.currentText() != '':
            Interface = str(cbIface.currentText())
        else:
            Interface = None

        ############
        ## Create Sourcecode

        if Interface == None:
            self.sourcecode = self.sourcecode
        else:
            self.sourcecode = (self.sourcecode+
                               ', iface=\''+Interface+'\'')

        self.sourcecode = ('sendp('+self.sourcecode+')')

        ##########
        ## send or save (pcap og Clipbord)

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
        elif Type == 1:
            ## save as .pcap
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
        else:
            ## save to Clipboard
            Clipboard = QtGui.QApplication.clipboard()
            Clipboard.setText(self.sourcecode)

        ## show sourcecode
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
                if self.ExtHdr[d][3] == 0:
                    self.M_Flag = '0'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.ExtHdr[d][3], offset = int(self.ExtHdr[d][1]), id = int(self.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 0, offset = int(self.ExtHdr[d][1]), id = int(self.ExtHdr[d][2]))
                else:
                    self.M_Flag = '1'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.ExtHdr[d][3], offset = int(self.ExtHdr[d][1]), id = int(self.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 1, offset = int(self.ExtHdr[d][1]), id = int(self.ExtHdr[d][2]))
                self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrFragment(m=' + 
                                  str(self.M_Flag) + ',offset=' + 
                                  str(self.ExtHdr[d][1]) + ',id=' + 
                                  str(self.ExtHdr[d][2]) + ')')
        return(ExtensionHeader)

    ###############
    ## Build ICMPv6

    def BuildNextHeader(self):

        if self.NextHeader_Type.currentText() == 'ICMP':
            if self.NH_ICMP_Ping.isChecked():
                NextHeader = self.BuildICMPv6_Ping()
            elif self.NH_ICMP_RouterAd.isChecked():
                NextHeader = self.BuildICMPv6_RA()
            elif self.NH_ICMP_PacketTooBig.isChecked():
                NextHeader = self.BuildICMPv6_PacketTooBig()
        elif self.NextHeader_Type.currentText() == 'TCP':
            NextHeader = self.BuildTCP()
        elif self.NextHeader_Type.currentText() == 'UDP':
            NextHeader = self.BuildUDP()
        elif self.NextHeader_Type.currentText() == 'No Next Header':
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

        enMTU = self.NH_ICMP_MTU
        if enMTU.text() != '':
            MTU = enMTU.text()
        else:
            MTU = None
        q=ICMPv6PacketTooBig(mtu=int(MTU))
        self.sourcecode = self.sourcecode+' /ICMPv6PacketTooBig(mtu='+MTU+')'

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
            self.sourcecode = (self.sourcecode+' /rdpcap(\''+path+'\')['+
                               str(no)+'][IPv6]')
        return(q)

    ## TCP

    def BuildTCP(self):
        if self.NH_TCP_SrcPort.text() != '':
            SPort=int(self.NH_TCP_SrcPort.text())
        else:
            self.NH_TCP_SrcPort.setText('20')
            SPort=int(self.NH_TCP_SrcPort.text())
        if self.NH_TCP_DstPort.text() != '':
            DPort=int(self.NH_TCP_DstPort.text())
        else:
            self.NH_TCP_DstPort.setText('80')
            DPort=int(self.NH_TCP_DstPort.text())
        Flags=0
        if self.NH_TCP_Flag_URG.isChecked():
            Flags = Flags + 32
        if self.NH_TCP_Flag_ACK.isChecked():
            Flags = Flags + 16
        if self.NH_TCP_Flag_PSH.isChecked():
            Flags = Flags + 8
        if self.NH_TCP_Flag_RST.isChecked():
            Flags = Flags + 4
        if self.NH_TCP_Flag_SYN.isChecked():
            Flags = Flags + 2
        if self.NH_TCP_Flag_FIN.isChecked():
            Flags = Flags + 1
        tcp= TCP(sport=SPort, dport=DPort, flags=Flags)
        self.sourcecode = self.sourcecode+'/TCP(sport='+str(SPort)+', dport='+str(DPort)+', flags='+str(Flags)+')'
        if self.NH_TCP_Payload_NoPayload.isChecked():
            return(tcp)
        elif self.NH_TCP_Payload_XLength.isChecked():
            load = 'X'*int(self.NH_TCP_Payload_Length.text())
            self.sourcecode = self.sourcecode+'/\'X\'*'+self.NH_TCP_Payload_Length.text()
            return(tcp/load)
        elif self.NH_TCP_Payload_PayString.isChecked():
            load = str(self.NH_TCP_Payload_String.text())
            self.sourcecode = self.sourcecode+'/\''+self.NH_TCP_Payload_String.text()+'\''
            return(tcp/load)
        elif self.NH_TCP_Payload_PcapFile.isChecked():
            path = self.PayloadFile['Capture File']
            capture = rdpcap(str(path))
            PCAPno = self.PayloadFile['Packet No.']
            if PCAPno != '':
                no = int(PCAPno)-1
            else:
                no = 0
            load = capture[no][Raw]
            self.sourcecode = (self.sourcecode+' /rdpcap(\''+path+'\')['+
                               str(no)+'][Raw]')
            return(tcp/load)

    ## UDP

    def BuildUDP(self):
        if self.NH_UDP_SrcPort.text() != '':
            SPort=int(self.NH_UDP_SrcPort.text())
        else:
            self.NH_UDP_SrcPort.setText('53')
            SPort=int(self.NH_UDP_SrcPort.text())
        if self.NH_UDP_DstPort.text() != '':
            DPort=int(self.NH_UDP_DstPort.text())
        else:
            self.NH_UDP_DstPort.setText('53')
            DPort=int(self.NH_UDP_DstPort.text())
        udp= UDP(sport=SPort, dport=DPort)
        self.sourcecode = self.sourcecode+'/UDP(sport='+str(SPort)+' ,dport='+str(DPort)+')'
        if self.NH_UDP_Payload_NoPayload.isChecked():
            return(udp)
        elif self.NH_UDP_Payload_XLength.isChecked():
            load = 'X' * int(self.NH_UDP_Payload_Length.text())
            self.sourcecode = self.sourcecode+'/\'X\'*'+self.NH_UDP_Payload_Length.text()
            return(udp/load)
        elif self.NH_UDP_Payload_PayString.isChecked():
            load = str(self.NH_UDP_Payload_String.text())
            self.sourcecode = self.sourcecode+'/\''+self.NH_UDP_Payload_String.text()+'\''
            return(udp/load)
        elif self.NH_UDP_Payload_PcapFile.isChecked():
            path = self.PayloadFile['Capture File']
            capture = rdpcap(str(path))
            PCAPno = self.PayloadFile['Packet No.']
            if PCAPno != '':
                no = int(PCAPno)-1
            else:
                no = 0
            load = capture[no][Raw]
            self.sourcecode = (self.sourcecode+' /rdpcap(\''+path+'\')['+
                               str(no)+'][Raw]')
            return(udp/load)

    ## No Next Header

    def BuildNoNextHeader(self):
        self.sourcecode = self.sourcecode
        return(None)

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    m = Main()
    app.exec_()
