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
import thread

class EH(QtGui.QDialog):
    """Extension Header"""
    def __init__(self, ExtHdr):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Extension Header")
        self.ExtHdr = ExtHdr
        self.Label = QtGui.QLabel("Extension Header:", self)
        self.Label.move(5, 5)
        self.ExtensionHdr = QtGui.QComboBox(self)
        self.ExtensionHdr.addItem('Hop By Hop Options')
        self.ExtensionHdr.addItem('Destination Options')
        self.ExtensionHdr.addItem('Routing')
        self.ExtensionHdr.addItem('Fragmentation')
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
        self.FragmentHdr_FragOffset.setInputMask('9999')
        self.connect(self.FragmentHdr_FragOffset, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_13)
        self.FragmentHdr_Label_2 = QtGui.QLabel("Identification:", self.FragmentHdr)
        self.FragmentHdr_Label_2.move(5, 80)
        self.FragmentHdr_ID = QtGui.QLineEdit('0', self.FragmentHdr)
        self.FragmentHdr_ID.setGeometry(QtCore.QRect(10, 105, 300, 30))
        self.FragmentHdr_ID.setInputMask('9999999999')
        self.connect(self.FragmentHdr_ID, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32)
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

    def slotMax2_32(self):
        """Diese Fuktion setzt den maximalen Wert eines Line Edit Widget auf 4294967296 (2^32 - 1).
        """
        if int(self.FragmentHdr_ID.text()) >= 4294967296: 
            self.FragmentHdr_ID.setText('4294967295')

    def slotMax2_13(self):
        """Diese Fuktion setzt den maximalen Wert eines Line Edit Widget auf 8191 (2^13 - 1).
        """
        if int(self.FragmentHdr_FragOffset.text()) >= 8192: 
            self.FragmentHdr_FragOffset.setText('8191')

class NS(QtGui.QDialog):
    """Neighbor Solicitation"""
    def __init__(self,NSconf):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Neighbor Solicitation")
        self.resize(320, 120)
        self.NSconf = NSconf
        self.Label = QtGui.QLabel("ICMPv6 Source Link-Layer-Address:", self)
        self.Label.move(5, 10)
        self.LLSrcAddr_help = QtGui.QLineEdit(self)
        self.LLSrcAddr_help.setInputMask('HH:HH:HH:HH:HH:HH')
        self.LLSrcAddr = QtGui.QComboBox(self)
        self.LLSrcAddr.setLineEdit(self.LLSrcAddr_help)
        self.LLSrcAddr.setGeometry(QtCore.QRect(10, 35, 300, 30))
        self.LLSrcAddr.setEditable(True)

        ## init cbSrcLLaddr
        iflist = get_if_list()
        i = len(iflist)
        self.LLSrcAddr.addItem('::')
        for d in range(0, i):
            self.LLSrcAddr.addItem(get_if_hwaddr(iflist[d]))
        self.LLSrcAddr.setEditText(self.NSconf['NS_LLSrcAddr'])

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(111, 80, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        self.show()

    def fertig(self):
        
        self.NSconf['NS_LLSrcAddr'] = self.LLSrcAddr.currentText()
        if self.NSconf['NS_LLSrcAddr'] == '': self.NSconf['NS_LLSrcAddr'] = '::'
        self.accept()

class NA(QtGui.QDialog):
    """Neighbor Advertisment"""
    def __init__(self,NAconf):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Neighbor Advertisement")
        self.resize(320, 220)
        self.NAconf = NAconf
        self.Label = QtGui.QLabel("Target Address:", self)
        self.Label.move(5, 10)
        self.tgtAddr = QtGui.QComboBox(self)
        self.tgtAddr.setGeometry(QtCore.QRect(10, 35, 300, 30))
        self.tgtAddr.setEditable(True)
        self.tgtAddr.addItem('')
        self.tgtAddr.addItem('ff01::1')
        self.tgtAddr.addItem('ff02::1')
        self.tgtAddr.addItem('ff80::1')
        self.RFlag = QtGui.QCheckBox("Router - flag", self)
        self.RFlag.move(10, 80)
        self.RFlag.setChecked(self.NAconf['R'])
        self.SFlag = QtGui.QCheckBox("Solicited - flag", self)
        self.SFlag.move(10, 100)
        self.SFlag.setChecked(self.NAconf['S'])
        self.OFlag = QtGui.QCheckBox("Override - flag", self)
        self.OFlag.move(10, 120)
        self.OFlag.setChecked(self.NAconf['O'])
        
        ## get IPv6 Dst-Addresses, add them to the drop-down list
        ipv6 = read_routes6()
        length_ipv6 = len(ipv6)
        for d in range(0, length_ipv6):
            if ipv6[d][2] != '::':
                self.tgtAddr.addItem(str(ipv6[d][2]))
        for d in range(0, length_ipv6):
            if ipv6[d][1] != 0 and ipv6[d][1] != 128 and ipv6[d][0] != 'fe80::':
                self.tgtAddr.addItem(str(ipv6[d][0])+'1')

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(111, 180, 98, 27))
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.fertig)
        self.show()

    def fertig(self):
        
        self.NAconf['NA_tgtAddr'] = self.tgtAddr.currentText()
        if self.NAconf['NA_tgtAddr'] == '': self.NAconf['NA_tgtAddr'] = ':::::'
        self.NAconf['R'] = self.RFlag.isChecked()
        self.NAconf['S'] = self.SFlag.isChecked()
        self.NAconf['O'] = self.OFlag.isChecked()  
        self.accept()

class RA(QtGui.QDialog):
    """Router Advertisement"""
    def __init__(self,RAconf):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Router Advertisement")
        self.resize(320, 350)
        self.RAconf = RAconf
        self.Label = QtGui.QLabel("Prefix:", self)
        self.Label.move(5, 15)
        self.Label_2 = QtGui.QLabel("Prefix lenght:", self)
        self.Label_2.move(205, 15)
        self.Prefix = QtGui.QLineEdit(self)
        self.Prefix.setGeometry(QtCore.QRect(10, 40, 150, 25))
        self.Prefix.setText(self.RAconf['Prefix'])
        self.PrefixLen = QtGui.QLineEdit(self)
        self.PrefixLen.setGeometry(QtCore.QRect(210, 40, 60, 25)) 
        self.PrefixLen.setText(self.RAconf['Prefixlen'])
        self.PrefixLen.setInputMask('999')
        self.connect(self.PrefixLen, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_7)
        self.MFlag = QtGui.QCheckBox("Managed address configuration - flag", self)
        self.MFlag.move(10, 150)
        self.MFlag.setChecked(self.RAconf['M'])
        self.OFlag = QtGui.QCheckBox("Other configuration - flag", self)
        self.OFlag.move(10, 170)
        self.OFlag.setChecked(self.RAconf['O'])
        self.Label_3 = QtGui.QLabel("Cur Hop Limit:", self)
        self.Label_3.move(5, 80)
        self.CHLim = QtGui.QLineEdit(self)
        self.CHLim.setGeometry(QtCore.QRect(10, 105, 60, 25))
        self.CHLim.setText(self.RAconf['CHLim'])
        self.CHLim.setInputMask('999')
        self.connect(self.CHLim, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.Label_4 = QtGui.QLabel("Router Life Time:", self)
        self.Label_4.move(155, 80)
        self.RouterLifeTime = QtGui.QLineEdit(self)
        self.RouterLifeTime.setGeometry(QtCore.QRect(160, 105, 60, 25))
        self.RouterLifeTime.setText(self.RAconf['RouterLifeTime'])
        self.RouterLifeTime.setInputMask('99999')
        self.connect(self.RouterLifeTime, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_16)
       
        self.line = QtGui.QFrame(self)
        self.line.setGeometry(QtCore.QRect(5, 200, 310, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label_5 = QtGui.QLabel("optional:", self)
        self.Label_5.move(125, 210)
        self.Label_6 = QtGui.QLabel("ICMPv6 Option (Source Link-Layer-Address):", self)
        self.Label_6.move(5, 240)
        self.LLSrcAddr_help = QtGui.QLineEdit(self)
        self.LLSrcAddr_help.setInputMask('HH:HH:HH:HH:HH:HH')
        self.LLSrcAddr = QtGui.QComboBox(self)
        self.LLSrcAddr.setGeometry(QtCore.QRect(10, 265, 300, 30))
        self.LLSrcAddr.setLineEdit(self.LLSrcAddr_help)
        self.LLSrcAddr.setEditable(True)

        ## init cbSrcLLaddr
        iflist = get_if_list()
        i = len(iflist)
        self.LLSrcAddr.addItem('')
        for d in range(0, i):
            self.LLSrcAddr.addItem(get_if_hwaddr(iflist[d]))
        self.LLSrcAddr.setEditText(self.RAconf['RA_LLSrcAddr'])

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.setGeometry(QtCore.QRect(111, 310, 98, 27))
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
        self.RAconf['CHLim'] = self.CHLim.text()
        if self.RAconf['CHLim'] == '': self.RAconf['CHLim'] = '0'
        self.RAconf['RouterLifeTime'] = self.RouterLifeTime.text()
        if self.RAconf['RouterLifeTime'] == '': self.RAconf['RouterLifeTime'] = '1800'
        self.RAconf['RA_LLSrcAddr'] = self.LLSrcAddr.currentText()
        if self.RAconf['RA_LLSrcAddr'] == ':::::': self.RAconf['RA_LLSrcAddr'] = ''
        self.RAconf['M'] = self.MFlag.isChecked()
        self.RAconf['O'] = self.OFlag.isChecked()  
        self.accept()

    def slotMax2_16(self):
        """Diese Fuktion setzt den maximalen Wert eines Line Edit Widget auf 65535 (2^16 - 1).
        """
        if int(self.RouterLifeTime.text()) >= 65536: 
            self.RouterLifeTime.setText('65535')

    def slotMax2_8(self):
        """Diese Fuktion setzt den maximalen Wert eines Line Edit Widget auf 255 (2^8 - 1).
        """
        if int(self.CHLim.text()) >= 256: 
            self.CHLim.setText('255')

    def slotMax2_7(self):
        """Diese Fuktion setzt den maximalen Wert eines Line Edit Widget auf 128 (2^7).
        """
        if int(self.PrefixLen.text()) >= 129: 
            self.PrefixLen.setText('128')

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

class RoundTrip(QtGui.QDialog):
    """Round-Trip Time"""
    def __init__(self,DstAdd):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("TCP Ping")
        self.resize(320, 180)
        self.Label = QtGui.QLabel("IPv6 Destination Address:", self)
        self.Label.move(5, 10)
        self.IPv6_DstAddr = QtGui.QComboBox(self)
        self.IPv6_DstAddr.setGeometry(QtCore.QRect(10, 35, 300, 30))
        self.IPv6_DstAddr.setEditable(True)
        self.Label_3 = QtGui.QLabel("Paket Count:", self)
        self.Label_3.move(5, 110)
        self.pktcount = QtGui.QLineEdit("3", self)
        self.pktcount.setGeometry(QtCore.QRect(125, 106, 60, 25))
        self.pktcount.setInputMask('9')
        

        ## init Dst Add
        
        i = len(DstAdd)
        for d in range(0, i):
            if DstAdd[d] != ('::1' or 'fe80::1'):
                self.IPv6_DstAddr.addItem(DstAdd[d])

        self.PingButton = QtGui.QPushButton("Ping",self)
        self.PingButton.setGeometry(QtCore.QRect(50, 140, 98, 27))
        self.connect(self.PingButton, QtCore.SIGNAL('clicked()'), self.SendPing)
        self.CloseButton = QtGui.QPushButton("Close",self)
        self.CloseButton.setGeometry(QtCore.QRect(152, 140, 98, 27))
        self.connect(self.CloseButton, QtCore.SIGNAL('clicked()'), self.Close)

        self.show()

    def SendPing(self):
        
        if self.pktcount.text() == ('' or '0'):
            self.pktcount.setText('5')
        thread.start_new_thread(self.Ping, (self.pktcount.text(), ))
        ans = sniff(filter='ip6', timeout=int(self.pktcount.text()))
        request = []
        reply = []
        for paket in ans:
            if paket[IPv6].type == 128:
                request.append(paket)
            if paket[IPv6].type == 129:
                reply.append(paket)
        if reply == None:
            info = 'Host is down'
        else:
            if len(request) == len(reply) and len(reply) == int(self.pktcount.text()):
                d = 0
                timediff = []
                timediffstr = ''
                while d < len(request):
                    timediff.append((reply[d].time - request[d].time)*1000)
                    timediffstr = timediffstr + str((reply[d].time - request[d].time)*1000)+' ms\n'
                    d += 1
                info = 'The Round-Trip Time of the individual pings are: \n'+timediffstr+'\nThe mean Time is '+ str(sum(timediff)/int(self.pktcount.text())) +' ms.'
            else:
                info = 'One or more replies are missing or Scapy cannot send all Pakets!'
        self.msg = QtGui.QMessageBox.information(None, "Result!", info)

    def Ping(self, pktcount):  
        waittime = .1  
        ping = IPv6(dst=str(self.IPv6_DstAddr.currentText()))/ICMPv6EchoRequest()     
        ans = srloop(ping, timeout = waittime, count=int(pktcount))

    def Close(self):
        self.close()
