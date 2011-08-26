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
## Version: 1.4                                                         #
## Date:    26.08.2011                                                  #
##                                                                      #
#########################################################################

import sys
from PyQt4 import QtCore, QtGui, Qt
from scapy.all import *
import program_background
import program_help_gui

class Main(QtGui.QMainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        self.setWindowTitle("Scapy GUI")
        self.resize(600, 370)
        self.makeActions()
        self.makeMenu()

        self.IPv6DstList = QtCore.QStringList()
        self.IPv6 = program_background.IPv6Paket()

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
        self.LLDstAddr.setInputMask('HH:HH:HH:HH:HH:HH')
        self.LLDstAddr.setText('ff:ff:ff:ff:ff:ff')
        self.LLDstAddr.setGeometry(QtCore.QRect(10, 130, 300, 31))
        self.LLSrcAddr_help = QtGui.QLineEdit(self.tab_EthH)
        self.LLSrcAddr_help.setInputMask('HH:HH:HH:HH:HH:HH')
        self.LLSrcAddr = QtGui.QComboBox(self.tab_EthH)
        self.LLSrcAddr.setLineEdit(self.LLSrcAddr_help)
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
        self.IPv6_DstAddr.setDuplicatesEnabled(True)
        self.IPv6_DstAddr.addItem('')
        self.IPv6_DstAddr.addItem('ff01::1')
        self.IPv6_DstAddr.addItem('ff02::1')
        self.IPv6_DstAddr.addItem('ff80::1')
        self.IPv6DstList.append('')
        self.IPv6DstList.append('ff01::1')
        self.IPv6DstList.append('ff02::1')
        self.IPv6DstList.append('ff80::1')
        self.IPv6DstList.append('fe80::1')
        self.IPv6DstList.append('::1')
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
        self.NextHeader_Type.addItem('ICMP')
        self.NextHeader_Type.addItem('TCP')
        self.NextHeader_Type.addItem('UDP')
        self.NextHeader_Type.addItem('No Next Header')
        self.NextHeader_Type.move(10, 20)
                # ICMP Typ
        self.NH_ICMP = QtGui.QWidget(self.tab_NextHeader)
        self.NH_ICMP.setGeometry(QtCore.QRect(0, 60, 600, 250))
        self.NH_ICMP_Ping = QtGui.QRadioButton("Ping", self.NH_ICMP)
        self.NH_ICMP_Ping.move(30, 10)
        self.NH_ICMP_Ping.setChecked(True)
        self.NH_ICMP_RouterAd = QtGui.QRadioButton("Router Advertisement", self.NH_ICMP)
        self.NH_ICMP_RouterAd.move(30, 40)
        self.connect(self.NH_ICMP_RouterAd, QtCore.SIGNAL('clicked(bool)'), self.slotRouterAdvertisement)
        self.NH_ICMP_RouterSo = QtGui.QRadioButton("Router Solicitation", self.NH_ICMP)
        self.NH_ICMP_RouterSo.move(30, 70)
        self.NH_ICMP_NeighborAd = QtGui.QRadioButton("Neighbor Advertisment", self.NH_ICMP)
        self.NH_ICMP_NeighborAd.move(30, 100)
        self.connect(self.NH_ICMP_NeighborAd, QtCore.SIGNAL('clicked(bool)'), self.slotNeighborAd)
        self.NH_ICMP_NeighborSo = QtGui.QRadioButton("Neighbor Solicitation", self.NH_ICMP)
        self.NH_ICMP_NeighborSo.move(30, 130)
        self.connect(self.NH_ICMP_NeighborSo, QtCore.SIGNAL('clicked(bool)'), self.slotNeighborSo)
        self.NH_ICMP_PacketTooBig = QtGui.QRadioButton("Packet Too Big", self.NH_ICMP)
        self.NH_ICMP_PacketTooBig.move(30, 160)
        self.connect(self.NH_ICMP_PacketTooBig, QtCore.SIGNAL('clicked(bool)'), self.slotPayload)
        self.NH_ICMP_Unknown = QtGui.QRadioButton("other ICMP Type", self.NH_ICMP)
        self.NH_ICMP_Unknown.move(330, 10)
        self.NH_ICMP_Label = QtGui.QLabel("MTU:", self.NH_ICMP)
        self.NH_ICMP_Label.move(80, 185)
        self.NH_ICMP_MTU = QtGui.QLineEdit("1280", self.NH_ICMP)
        self.NH_ICMP_MTU.setInputMask('9999999999')
        self.NH_ICMP_MTU.setGeometry(QtCore.QRect(120, 181, 90, 25))
        self.NH_ICMP_Label_2 = QtGui.QLabel("Type:", self.NH_ICMP)
        self.NH_ICMP_Label_2.move(380, 40)
        self.NH_ICMP_Type = QtGui.QLineEdit("1", self.NH_ICMP)
        self.NH_ICMP_Type.setInputMask('000')
        self.NH_ICMP_Type.setGeometry(QtCore.QRect(420, 36, 60, 25))
        self.NH_ICMP_Label_3 = QtGui.QLabel("Code:", self.NH_ICMP)
        self.NH_ICMP_Label_3.move(377, 70)
        self.NH_ICMP_Code = QtGui.QLineEdit("0", self.NH_ICMP)
        self.NH_ICMP_Code.setInputMask('000')
        self.NH_ICMP_Code.setGeometry(QtCore.QRect(420, 66, 60, 25))
        self.NH_ICMP_Label_4 = QtGui.QLabel("Message:", self.NH_ICMP)
        self.NH_ICMP_Label_4.move(352, 100)
        self.NH_ICMP_Message = QtGui.QTextEdit("", self.NH_ICMP)
        self.NH_ICMP_Message.setGeometry(QtCore.QRect(420, 96, 150, 50))
        self.connect(self.NH_ICMP_MTU, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32)
        self.connect(self.NH_ICMP_Type, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.connect(self.NH_ICMP_Code, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)

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
        self.NH_TCP_Payload_Length.setInputMask('00000')
        self.NH_TCP_Payload_Length.setGeometry(QtCore.QRect(120, 56, 60, 25))
        self.NH_TCP_Payload_PayString = QtGui.QRadioButton("String:", self.NH_TCP_Payload)
        self.NH_TCP_Payload_PayString.move(30, 90)
        self.NH_TCP_Payload_String = QtGui.QLineEdit("X", self.NH_TCP_Payload)
        self.NH_TCP_Payload_String.setGeometry(QtCore.QRect(120, 88, 60, 25))
        self.NH_TCP_Payload_PcapFile = QtGui.QRadioButton("pcap File", self.NH_TCP_Payload)
        self.NH_TCP_Payload_PcapFile.move(30, 130)
        self.connect(self.NH_TCP_Payload_PcapFile, QtCore.SIGNAL('clicked(bool)'), self.slotPayload)
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
        self.NH_TCP_Payload_Length.setInputMask('00000')
        self.NH_UDP_Payload_Length.setGeometry(QtCore.QRect(120, 56, 60, 25))
        self.NH_UDP_Payload_PayString = QtGui.QRadioButton("String:", self.NH_UDP_Payload)
        self.NH_UDP_Payload_PayString.move(30, 90)
        self.NH_UDP_Payload_String = QtGui.QLineEdit("X", self.NH_UDP_Payload)
        self.NH_UDP_Payload_String.setGeometry(QtCore.QRect(120, 88, 60, 25))
        self.NH_UDP_Payload_PcapFile = QtGui.QRadioButton("pcap File", self.NH_UDP_Payload)
        self.NH_UDP_Payload_PcapFile.move(30, 130)
        self.connect(self.NH_UDP_Payload_PcapFile, QtCore.SIGNAL('clicked(bool)'),self.slotPayload)
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
        self.Interface.addItem('')
        for d in iflist:
            self.Interface.addItem(d)

        ## get SourceLinkLayerAddresses, add them to the drop-down list
        i = len(iflist)
        self.LLSrcAddr.addItem('')
        for d in range(0, i):
            self.LLSrcAddr.addItem(get_if_hwaddr(iflist[d]))

        ## get IPv6 Addresses, add them to the drop-down list
        ipv6 = read_routes6()
        length_ipv6 = len(ipv6)
        for d in range(0, length_ipv6):
            if ipv6[d][3] == 'lo':
                self.IPv6_SrcAddr.addItem(str(ipv6[d][0]))
        for d in range(0, length_ipv6):
            if ipv6[d][2] != '::' and self.IPv6DstList.contains(ipv6[d][2]) == False:
                self.IPv6_DstAddr.addItem(str(ipv6[d][2]))
                self.IPv6DstList.append(str(ipv6[d][2]))
        for d in range(0, length_ipv6):
            if ipv6[d][1] != (0 or 128) and self.IPv6DstList.contains(str(ipv6[d][0])+'1') == False:
                self.IPv6_DstAddr.addItem(str(ipv6[d][0])+'1')
                self.IPv6DstList.append(str(ipv6[d][0])+'1')

    def slotMax2_32(self):
        """Diese Fuktion setzt den maximalen Wert eines Line Edit Widget auf 4294967296 (2^32 - 1).
        """
        if int(self.NH_ICMP_MTU.text()) >= 4294967296: 
            self.NH_ICMP_MTU.setText('4294967295')

    def slotMax2_8(self):
        """Diese Fuktion setzt den maximalen Wert einiger Line Edit Widget auf 255 (2^8 - 1).
        """
        if int(self.NH_ICMP_Type.text()) >= 256: 
            self.NH_ICMP_Type.setText('255')
        if int(self.NH_ICMP_Code.text()) >= 256: 
            self.NH_ICMP_Code.setText('255')

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
        """In dieser Fuktion werden Aktionen mit der Menubar verknüpft.
        """
        self._saveAction = QtGui.QAction("&Save", None)
        self._loadAction = QtGui.QAction("&Load", None)
        self._exitAction = QtGui.QAction("&Exit", None)
        self._getIPv6AddrAction = QtGui.QAction("&Get lokal IPv6 Addresses", None)
        self._RoundTripAction = QtGui.QAction("&Round-Trip Time", None)
        self.connect(self._saveAction, QtCore.SIGNAL('triggered()'), self.slotSave)
        self.connect(self._loadAction, QtCore.SIGNAL('triggered()'), self.slotLoad)
        self.connect(self._exitAction, QtCore.SIGNAL('triggered()'), self.slotClose)
        self.connect(self._getIPv6AddrAction, QtCore.SIGNAL('triggered()'), self.slotGetIPv6Addr)
        self.connect(self._RoundTripAction, QtCore.SIGNAL('triggered()'), self.slotRoundTrip)

    def makeMenu(self):
        """Diese Fuktion erstellt die Menubar.
        """
        menuBar = self.menuBar()
        fileMenu = menuBar.addMenu("&File")
        fileMenu.addAction(self._saveAction)
        fileMenu.addAction(self._loadAction)
        fileMenu.addAction(self._exitAction)
        toolMenu = menuBar.addMenu("&Tool")
        toolMenu.addAction(self._getIPv6AddrAction)
        toolMenu.addAction(self._RoundTripAction)

    def slotAddExtHdr(self):
        """Ruft die Einstellung der Extension Header auf"""
        self.setEnabled(False)
        Rows = len(self.IPv6.ExtHdr)
        eh = program_help_gui.EH(self.IPv6.ExtHdr[Rows-1])
        eh.exec_()
        if self.IPv6.ExtHdr[Rows-1][0] != '':
            numRows = self.ExtHdr_tableWidget.rowCount()
            self.ExtHdr_tableWidget.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.IPv6.ExtHdr[Rows-1][0])
            self.ExtHdr_tableWidget.setItem(numRows, 0, t1)
            item = self.ExtHdr_tableWidget.item(numRows, 0)
            item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
            item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
            self.IPv6.ExtHdr.append(['','','',''])
        self.setEnabled(True)

    def slotEditExtHdr(self):
        Row = self.ExtHdr_tableWidget.currentRow()
        if Row != -1:
            self.setEnabled(False)
            eh = program_help_gui.EH(self.IPv6.ExtHdr[Row])
            eh.exec_()
            t1 = QtGui.QTableWidgetItem(self.IPv6.ExtHdr[Row][0])
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
            del self.IPv6.ExtHdr[Row]
            self.ExtHdr_tableWidget.setCurrentCell(Row,0)

    def slotRouterAdvertisement(self):
        """Ruft ein Fenster für Router Advertisement auf"""
        self.setEnabled(False)
        ra = program_help_gui.RA(self.IPv6.RAconf)
        ra.exec_()
        self.setEnabled(True)

    def slotNeighborSo(self):
        """Ruft ein Fenster für Neighbor Solicitation auf"""
        self.setEnabled(False)
        ns = program_help_gui.NS(self.IPv6.NSconf)
        ns.exec_()
        self.setEnabled(True)

    def slotNeighborAd(self):
        """Ruft ein Fenster für Neighbor Advertisment auf"""
        self.setEnabled(False)
        na = program_help_gui.NA(self.IPv6.NAconf)
        na.exec_()
        self.setEnabled(True)

    def slotPayload(self):
        """Ruft die Paylaod Einstellungen auf"""
        self.setEnabled(False)
        payload = program_help_gui.Payload(self.IPv6.Payload)
        payload.exec_()
        if ((self.IPv6.Payload['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
            self.NH_TCP_Payload_XLength.setChecked(True)
            self.NH_UDP_Payload_XLength.setChecked(True)
            self.NH_ICMP_Ping.setChecked(True)
        self.setEnabled(True)

    def slotGetIPv6Addr(self):
        """Diese Funktion enthält ein Werkzeug, mit dessen Hilfe die lokalen IPv6 Addressen ermittelt und in die entsprechende ComboBox hizugefügt werden."""
        addresses=[]
        request = Ether()/IPv6(dst='ff02::1')/ICMPv6EchoRequest()
        ans, unans = srp(request, multi = 1, timeout = 10)
        query = Ether()/IPv6(dst='ff02::1',hlim=1)/IPv6ExtHdrHopByHop(autopad=0,nh=58)/ICMPv6MLQuery()
        query[2].options='\x05\x02\x00\x00\x00\x00'
        sendp(query)
        ans2 = sniff(filter='ip6[48]=131', timeout=10)
        if ans != None:
            for paket in ans:
                addresses.append(paket[1][IPv6].src)
        if ans2 != None:
            for paket in ans2:
                addresses.append(paket[IPv6].src)
        uniqueAddr = set(addresses)
        for address in uniqueAddr:
            if self.IPv6DstList.contains(address) == False:
                self.IPv6_DstAddr.addItem(str(address)) 
                self.IPv6DstList.append(str(address))

    def slotRoundTrip(self):
        """Diese Funktion öffnet ein Werkzeug, mit dessen Hilfe ein Ping mit TCP erzeugt und die benötigte Zeit angegeben wird"""
        RoundTrip = program_help_gui.RoundTrip(self.IPv6DstList)
        RoundTrip.exec_()

    def slotSave(self):
        """Wird aufgerufen, um alle eingestellten Daten zu speichern."""
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "",("pcap(*.pcap)"))
        if filename != '':
            if filename.endsWith('.pcap') == False:
                filename=(filename+'.pcap')
            self.creatIPv6(1, filename)

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
        self.IPv6.ExtHdr = [['','','','']]
        d = 0
        temp = 0
        count = 0
        while count < 1:
            if self.NextHeader == 0:
                temp = Data.nh
                self.IPv6.ExtHdr[d][0] = 'Hop By Hop Options'
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.IPv6.ExtHdr[d][0])
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
                self.IPv6.ExtHdr[d][0] = 'Routing'
                self.IPv6.ExtHdr[d][1] = Data.addresses
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.IPv6.ExtHdr[d][0])
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
                self.IPv6.ExtHdr[d][0] = 'Fragmentation'
                self.IPv6.ExtHdr[d][1] = Data.offset
                self.IPv6.ExtHdr[d][2] = Data.id
                self.IPv6.ExtHdr[d][3] = Data.m
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.IPv6.ExtHdr[d][0])
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
                self.IPv6.ExtHdr[d][0] = 'Destination Options'
                numRows = self.ExtHdr_tableWidget.rowCount()
                self.ExtHdr_tableWidget.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.IPv6.ExtHdr[d][0])
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
                    self.IPv6.RAconf['Prefix'] = Data.prefix
                    self.IPv6.RAconf['Prefixlen'] = Data.prefixlen
                    self.IPv6.RAconf['CHLim'] = Data.chlim
                    if Data.M == 1: self.IPv6.RAconf['M'] = True
                    else: self.IPv6.RAconf['M'] = False
                    if Data.O == 1: self.IPv6.RAconf['O'] = True
                    else: self.IPv6.RAconf['O'] = False
                elif Data.type == 135:
                    self.NH_ICMP_NeighborSo.setChecked(True)
                    self.IPv6.NSconf['NS_LLSrcAddr'] = Data.tgt
                elif Data.type == 2:
                    self.NH_ICMP_PacketTooBig.setChecked(True)
                    self.NH_ICMP_MTU.setText(str(Data.mtu))
                else:
                    self.NH_ICMP_Unknown.setChecked(True)
                    self.NH_ICMP_Type.setText(str(Data.type))
                    self.NH_ICMP_Code.setText(str(Data.code))
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
        """Wird aufgerufen, um alle eingestellten Daten zu senden."""
        self.creatIPv6(0, '')

    def slotClipboard(self):
        """Wird aufgerufen, um alle eingestellten Daten in den Zwischenspeicher zu speichern."""
        self.creatIPv6(2, '')

    def slotClose(self):
        """Wird aufgerufen, wenn das Fenster geschlossen wird"""
        ret = QtGui.QMessageBox.question(None, "Quit?", "You want to close this program?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if ret == QtGui.QMessageBox.Yes:
            self.close()

    def creatIPv6(self, Option, File):
        """Erstellen des IPv6 Paketes in einer Datei für spätere Weiterverarbeitung und 
        ruft die Funktion :class:`Buildit` auf.
        """
        self.IPv6.EthHdr['LLDstAddr'] = str(self.LLDstAddr.text())
        self.IPv6.EthHdr['LLSrcAddr'] = str(self.LLSrcAddr.currentText())
        self.IPv6.EthHdr['Interface'] = str(self.Interface.currentText())
        self.IPv6.IPHdr['DstIPAddr'] = str(self.IPv6_DstAddr.currentText())
        self.IPv6.IPHdr['SrcIPAddr'] = str(self.IPv6_SrcAddr.currentText())
        if self.IPv6.EthHdr['LLDstAddr'] == 'ff:ff:ff:ff:ff:ff': self.IPv6.EthHdr['LLDstAddr'] = None
        if self.IPv6.EthHdr['LLSrcAddr'] == ':::::': self.IPv6.EthHdr['LLSrcAddr'] = None
        if self.IPv6.IPHdr['SrcIPAddr'] == '': self.IPv6.IPHdr['SrcIPAddr'] = None
        if self.IPv6.IPHdr['DstIPAddr'] == '':
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Destination Address is requiered\nto create a valid package!")
            return
        if self.NextHeader_Type.currentText() == 'ICMP':
            self.IPv6.indize = 0
            if self.NH_ICMP_Ping.isChecked():
                self.IPv6.ICMP['indize'] = 0
            elif self.NH_ICMP_RouterAd.isChecked():
                self.IPv6.ICMP['indize'] = 1
            elif self.NH_ICMP_RouterSo.isChecked():
                self.IPv6.ICMP['indize'] = 2
            elif self.NH_ICMP_NeighborAd.isChecked():
                self.IPv6.ICMP['indize'] = 3
            elif self.NH_ICMP_NeighborSo.isChecked():
                self.IPv6.ICMP['indize'] = 4
            elif self.NH_ICMP_PacketTooBig.isChecked():
                self.IPv6.ICMP['indize'] = 5
                self.IPv6.PTB['MTU'] = self.NH_ICMP_MTU.text()
            elif self.NH_ICMP_Unknown.isChecked():
                self.IPv6.ICMP['indize'] = 6
                self.IPv6.ICMP['Type'] = self.NH_ICMP_Type.text()
                self.IPv6.ICMP['Code'] = self.NH_ICMP_Code.text()
                if self.IPv6.ICMP['Type'] == '':self.IPv6.ICMP['Type'] = '1'
                if self.IPv6.ICMP['Code'] == '': self.IPv6.ICMP['Code'] = '0'
                self.IPv6.ICMP['Message'] = str(self.NH_ICMP_Message.toPlainText())
        elif self.NextHeader_Type.currentText() == 'TCP':
            self.IPv6.indize = 1
            if self.NH_TCP_SrcPort.text() == '': self.NH_TCP_SrcPort.setText('20')
            if self.NH_TCP_DstPort.text() == '': self.NH_TCP_DstPort.setText('80')
            self.IPv6.TCP_UDP['SrcPort'] = self.NH_TCP_SrcPort.text()
            self.IPv6.TCP_UDP['DstPort'] = self.NH_TCP_DstPort.text()
            if self.NH_TCP_Payload_XLength.isChecked():
                self.IPv6.Payload['indizeP'] = 0
                self.IPv6.Payload['Payloadlen'] = self.NH_TCP_Payload_Length.text()
            elif self.NH_TCP_Payload_PayString.isChecked():
                self.IPv6.Payload['indizeP'] = 1
                self.IPv6.Payload['PayloadString'] = self.NH_TCP_Payload_String.text()
            elif self.NH_TCP_Payload_PcapFile.isChecked():
                self.IPv6.Payload['indizeP'] = 2
            elif self.NH_TCP_Payload_NoPayload.isChecked():
                self.IPv6.Payload['indizeP'] = 3
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
            self.IPv6.TCP_UDP['Flags'] = Flags            
        elif self.NextHeader_Type.currentText() == 'UDP':
            self.IPv6.indize = 2
            if self.NH_UDP_SrcPorttext() == '': self.NH_UDP_SrcPort.setText('53')
            if self.NH_UDP_DstPorttext() == '': self.NH_UDP_DstPort.setText('53')
            self.IPv6.TCP_UDP['SrcPort'] = self.NH_UDP_SrcPort.text()
            self.IPv6.TCP_UDP['DstPort'] = self.NH_UDP_DstPort.text()
            if self.NH_UDP_Payload_XLength.isChecked():
                self.IPv6.Payload['indizeP'] = 0
                self.IPv6.Payload['Payloadlen'] = self.NH_UDP_Payload_Length.text()
            elif self.NH_UDP_Payload_PayString.isChecked():
                self.IPv6.Payload['indizeP'] = 1
                self.IPv6.Payload['PayloadString'] = self.NH_UDP_Payload_String.text()
            elif self.NH_UDP_Payload_PcapFile.isChecked():
                self.IPv6.Payload['indizeP'] = 2
            elif self.NH_UDP_Payload_NoPayload.isChecked():
                self.IPv6.Payload['indizeP'] = 3
        elif self.NextHeader_Type.currentText() == 'No Next Header':
            self.IPv6.indize = 3

        program_background.Buildit(Option, File, self.IPv6)



if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    m = Main()
    app.exec_()
