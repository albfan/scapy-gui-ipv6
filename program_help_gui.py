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
## Version: 2.2                                                         #
## Date:    23.11.2011                                                  #
##                                                                      #
#########################################################################

import sys
from PyQt4 import QtCore, QtGui, Qt
from scapy.all import *
import thread

class EH(QtGui.QDialog):
    """The class ``EH`` extension header opens a popup window where 4 different extension header types can be chosen.

    :param ExtHdr: is an array to save information for the different EH types 

    The possible types are Hob by Hop Option -, Destination Option - , Routing - and Fragmentation Header.
    The Hop by Hop and Destination Option Header build only the option type PadN.
    At the Routing Header is at least one IPv6 address necessary (more are possible).
    At the Fragmentation Header you can set the offset, ID and M-flag.
"""
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
        self.HopByHopHdr_Option = QtGui.QComboBox(self.HopByHopHdr)
        self.HopByHopHdr_Option.addItem('PadN Option')
        self.HopByHopHdr_Option.addItem('Pad1 Option')
        self.HopByHopHdr_Option.addItem('other Option')
        self.HopByHopHdr_Option.move(10, 15)
        self.HopByHopHdr_2 = QtGui.QWidget(self.HopByHopHdr)
        self.HopByHopHdr_2.setGeometry(QtCore.QRect(0, 30, 360, 220))
        self.HopByHopHdr_Label = QtGui.QLabel("Option Type:", self.HopByHopHdr_2)
        self.HopByHopHdr_Label.move(5,30)
        self.HopByHopHdr_Label_2 = QtGui.QLabel("Option Length:", self.HopByHopHdr_2)
        self.HopByHopHdr_Label_2.move(155,30)
        self.HopByHopHdr_Label_3 = QtGui.QLabel("Option Data:", self.HopByHopHdr_2)
        self.HopByHopHdr_Label_3.move(5,100)
        self.HopByHopHdr_OptType = QtGui.QLineEdit('1', self.HopByHopHdr_2)
        self.HopByHopHdr_OptType.setGeometry(QtCore.QRect(10, 55, 60, 31))
        self.HopByHopHdr_OptType.setInputMask('999')
        self.HopByHopHdr_OptLen = QtGui.QLineEdit('4', self.HopByHopHdr_2)
        self.HopByHopHdr_OptLen.setGeometry(QtCore.QRect(160, 55, 60, 31))
        self.HopByHopHdr_OptLen.setInputMask('999')
        self.HopByHopHdr_OptData = QtGui.QTextEdit('\x00\x00\x00\x00', self.HopByHopHdr_2)
        self.HopByHopHdr_OptData.setGeometry(QtCore.QRect(10, 125, 250, 50))
        self.HopByHopHdr_OptData.setText('\\x00\\x00\\x00\\x00')
        self.connect(self.HopByHopHdr_Option, QtCore.SIGNAL('activated(int)'), self.HopByHopConf)
        self.connect(self.HopByHopHdr_OptType, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.connect(self.HopByHopHdr_OptLen, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)

        ## Destination Header
        self.DestinationHdr = QtGui.QWidget(self)
        self.DestinationHdr.setGeometry(QtCore.QRect(0, 60, 360, 250))
        self.DestinationHdr_Option = QtGui.QComboBox(self.DestinationHdr)
        self.DestinationHdr_Option.addItem('PadN Option')
        self.DestinationHdr_Option.addItem('Pad1 Option')
        self.DestinationHdr_Option.addItem('other Option')
        self.DestinationHdr_Option.move(10, 15)
        self.DestinationHdr_2 = QtGui.QWidget(self.DestinationHdr)
        self.DestinationHdr_2.setGeometry(QtCore.QRect(0, 30, 360, 220))
        self.DestinationHdr_Label = QtGui.QLabel("Option Type:", self.DestinationHdr_2)
        self.DestinationHdr_Label.move(5,30)
        self.DestinationHdr_Label_2 = QtGui.QLabel("Option Length:", self.DestinationHdr_2)
        self.DestinationHdr_Label_2.move(155,30)
        self.DestinationHdr_Label_3 = QtGui.QLabel("Option Data:", self.DestinationHdr_2)
        self.DestinationHdr_Label_3.move(5,100)
        self.DestinationHdr_OptType = QtGui.QLineEdit('1', self.DestinationHdr_2)
        self.DestinationHdr_OptType.setGeometry(QtCore.QRect(10, 55, 60, 31))
        self.DestinationHdr_OptType.setInputMask('999')
        self.DestinationHdr_OptLen = QtGui.QLineEdit('4', self.DestinationHdr_2)
        self.DestinationHdr_OptLen.setGeometry(QtCore.QRect(160, 55, 60, 31))
        self.DestinationHdr_OptLen.setInputMask('999')
        self.DestinationHdr_OptData = QtGui.QTextEdit('\x00\x00\x00\x00', self.DestinationHdr_2)
        self.DestinationHdr_OptData.setGeometry(QtCore.QRect(10, 125, 250, 50))
        self.DestinationHdr_OptData.setText('\\x00\\x00\\x00\\x00')
        self.connect(self.DestinationHdr_Option, QtCore.SIGNAL('activated(int)'), self.DestinationConf)
        self.connect(self.DestinationHdr_OptType, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.connect(self.DestinationHdr_OptLen, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)

        
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
        self.FragmentHdr_FragOffset.setGeometry(QtCore.QRect(10, 35, 60, 31))
        self.FragmentHdr_FragOffset.setInputMask('9999')
        self.connect(self.FragmentHdr_FragOffset, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_13)
        self.FragmentHdr_Label_2 = QtGui.QLabel("Identification:", self.FragmentHdr)
        self.FragmentHdr_Label_2.move(5, 80)
        self.FragmentHdr_ID = QtGui.QLineEdit('0', self.FragmentHdr)
        self.FragmentHdr_ID.setGeometry(QtCore.QRect(10, 105, 100, 30))
        self.FragmentHdr_ID.setInputMask('9999999999')
        self.connect(self.FragmentHdr_ID, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32)
        self.FragmentHdr_M = QtGui.QCheckBox("Last Package", self.FragmentHdr)
        self.FragmentHdr_M.move(10, 160)
        
        self.HopByHopHdr.setVisible(False)
        self.HopByHopHdr_2.setVisible(False)
        self.DestinationHdr.setVisible(False)
        self.DestinationHdr_2.setVisible(False)
        self.RoutingHdr.setVisible(False)
        self.FragmentHdr.setVisible(False)

        if self.ExtHdr[0] == '':
            self.HopByHopHdr.setVisible(True)
        elif self.ExtHdr[0] == 'Hop By Hop Options':
            self.ExtensionHdr.setCurrentIndex(0)
            self.HopByHopHdr.setVisible(True)
            if self.ExtHdr[1] == 'PadN Option':
                self.HopByHopHdr_Option.setCurrentIndex(0)
            elif self.ExtHdr[1] == 'Pad1 Option':
                self.HopByHopHdr_Option.setCurrentIndex(1)
            elif self.ExtHdr[1] == 'other Option':
                self.HopByHopHdr_Option.setCurrentIndex(2)
                self.HopByHopHdr_2.setVisible(True)
                self.HopByHopHdr_OptType.setText(str(self.ExtHdr[2]).split()[0])
                self.HopByHopHdr_OptLen.setText(str(self.ExtHdr[2]).split()[-1])
                self.HopByHopHdr_OptData.setPlainText(self.ExtHdr[3])
        elif self.ExtHdr[0] == 'Destination Options':
            self.ExtensionHdr.setCurrentIndex(1)
            self.DestinationHdr.setVisible(True)
            if self.ExtHdr[1] == 'PadN Option':
                self.DestinationHdr_Option.setCurrentIndex(0)
            elif self.ExtHdr[1] == 'Pad1 Option':
                self.DestinationHdr_Option.setCurrentIndex(1)
            elif self.ExtHdr[1] == 'other Option':
                self.DestinationHdr_Option.setCurrentIndex(2)
                self.DestinationHdr_2.setVisible(True)
                self.DestinationHdr_OptType.setText(str(self.ExtHdr[2]).split()[0])
                self.DestinationHdr_OptLen.setText(str(self.ExtHdr[2]).split()[-1])
                self.DestinationHdr_OptData.setPlainText(self.ExtHdr[3])
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
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.ready)
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

    def HopByHopConf(self):
        if self.HopByHopHdr_Option.currentText() == 'other Option':
            self.HopByHopHdr_2.setVisible(True)
        else:
            self.HopByHopHdr_2.setVisible(False)

    def DestinationConf(self):
        if self.DestinationHdr_Option.currentText() == 'other Option':
            self.DestinationHdr_2.setVisible(True)
        else:
            self.DestinationHdr_2.setVisible(False)

    def AddIP(self):
        """This funcion adds an IPv6 address from the adress field into the address array. (Routing Header)
"""
        numRows = self.RoutingHdr_AddrArray.rowCount()
        if numRows < 16:
            self.RoutingHdr_AddrArray.insertRow(numRows)
            t1 = QtGui.QTableWidgetItem(self.RoutingHdr_Address.text())
            self.RoutingHdr_AddrArray.setItem(numRows, 0, t1)
        else:
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")

    def DeleteIP(self):
        """A marked IPv6 address from the array can be deleted with this function. (Routing Header)
"""
        Row = self.RoutingHdr_AddrArray.currentRow()
        if Row >= 0:
            self.RoutingHdr_AddrArray.removeRow(Row)

    def ready(self):
        """If you are ready to configure an extension header, this function will handle the information in the right order and returns to the main window.
"""
        self.ExtHdr[0] = self.ExtensionHdr.currentText()
        self.addresses=[]
        if self.ExtHdr[0] == 'Hop By Hop Options':
            self.ExtHdr[1] = self.HopByHopHdr_Option.currentText()
            if self.ExtHdr[1] == 'other Option':
                if self.HopByHopHdr_OptType.text() == '':self. HopByHopHdr_OptType.setText('0')
                if self.HopByHopHdr_OptLen.text() == '':self. HopByHopHdr_OptLen.setText('0')
                self.ExtHdr[2] = self.HopByHopHdr_OptType.text() + ' ' + self.HopByHopHdr_OptLen.text()
                self.ExtHdr[3] = self.HopByHopHdr_OptData.toPlainText()
        elif self.ExtHdr[0] == 'Destination Options':
            self.ExtHdr[1] = self.DestinationHdr_Option.currentText()
            if self.ExtHdr[1] == 'other Option':
                if self.DestinationHdr_OptType.text() == '':self. DestinationHdr_OptType.setText('0')
                if self.DestinationHdr_OptLen.text() == '':self. DestinationHdr_OptLen.setText('0')
                self.ExtHdr[2] = self.DestinationHdr_OptType.text() + ' ' + self.DestinationHdr_OptLen.text()
                self.ExtHdr[3] = self.DestinationHdr_OptData.toPlainText()
        elif self.ExtHdr[0] == 'Routing':
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
        """This function sets the maximum Value of a Line Edit Widget to 4294967295 (2^32-1)
"""
        if self.FragmentHdr_ID.text() != '' and int(self.FragmentHdr_ID.text()) >= 4294967296: 
            self.FragmentHdr_ID.setText('4294967295')

    def slotMax2_13(self):
        """This function sets the maximum Value of a Line Edit Widget to 8191 (2^13 - 1).
        """
        if self.FragmentHdr_FragOffset.text() != '' and int(self.FragmentHdr_FragOffset.text()) >= 8192: 
            self.FragmentHdr_FragOffset.setText('8191')

    def slotMax2_8(self):
        """This function sets the maximum Value of a Line Edit Widget to 255 (2^8-1)
"""
        if self.HopByHopHdr_OptType.text() != '' and int(self.HopByHopHdr_OptType.text()) >= 256: 
            self.HopByHopHdr_OptType.setText('255')
        if self.HopByHopHdr_OptLen.text() != '' and int(self.HopByHopHdr_OptLen.text()) >= 256: 
            self.HopByHopHdr_OptLen.setText('255')
        if self.DestinationHdr_OptType.text() != '' and int(self.DestinationHdr_OptType.text()) >= 256: 
            self.DestinationHdr_OptType.setText('255')
        if self.DestinationHdr_OptLen.text() != '' and int(self.DestinationHdr_OptLen.text()) >= 256: 
            self.DestinationHdr_OptLen.setText('255')


class NDOptHdr(QtGui.QDialog):
    """The class ``NDOptHdr`` opens a popup window where the neighbor discovery options can be choosen.

    :param NDOpt: is an array to save all information for the ICMPv6 ND options
    :param Payload: save the pcap-file path for the IPv6 redirected packet

    There are five possible neighbor discovery options:
   
    * Source Link-layer Address,
    * Target Link-layer Address,
    * Prefix Information,
    * Redirected Header,
    * MTU,
    * Source Address List and
    * Target Address List.

    All this types can be added to the ICMPv6 messages 133, 134, 135, 136 and 137.  
"""
    def __init__(self, NDOpt, Payload):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Neighbor Discovery Options")
        height = 400
        width = 800
        self.resize(width, height)
        self.NDOpt = NDOpt
        self.Payload = Payload

        self.NDOpt_tabWidget = QtGui.QTabWidget(self)
        self.NDOpt_tabWidget.setGeometry(QtCore.QRect(0, 0, width, height-50))
                # Source Link layer Address
        self.NDOpt_SrcLLAddr = QtGui.QWidget(self.NDOpt_tabWidget)
        self.NDOpt_tabWidget.addTab(self.NDOpt_SrcLLAddr, "Source LL address")
        self.NDOpt_SrcLLAddr_Add = QtGui.QCheckBox("Add", self.NDOpt_SrcLLAddr)
        self.NDOpt_SrcLLAddr_Add.move(10, 10)
        self.Label = QtGui.QLabel("ICMPv6 Option Source Link-Layer-Address:", self.NDOpt_SrcLLAddr)
        self.Label.move(5, 50)
        self.NDOpt_SrcLLAddr_LLSrcAddr_help = QtGui.QLineEdit(self.NDOpt_SrcLLAddr)
        self.NDOpt_SrcLLAddr_LLSrcAddr_help.setInputMask('HH:HH:HH:HH:HH:HH')
        self.NDOpt_SrcLLAddr_LLSrcAddr = QtGui.QComboBox(self.NDOpt_SrcLLAddr)
        self.NDOpt_SrcLLAddr_LLSrcAddr.setGeometry(QtCore.QRect(10, 75, 300, 30))
        self.NDOpt_SrcLLAddr_LLSrcAddr.setLineEdit(self.NDOpt_SrcLLAddr_LLSrcAddr_help)
        self.NDOpt_SrcLLAddr_LLSrcAddr.setEditable(True)
                # Destination Link layer Address
        self.NDOpt_DstLLAddr = QtGui.QWidget(self.NDOpt_tabWidget)
        self.NDOpt_tabWidget.addTab(self.NDOpt_DstLLAddr, "Destination LL address")
        self.NDOpt_DstLLAddr_Add = QtGui.QCheckBox("Add", self.NDOpt_DstLLAddr)
        self.NDOpt_DstLLAddr_Add.move(10, 10)
        self.Label = QtGui.QLabel("ICMPv6 Option Destination Link-Layer-Address:", self.NDOpt_DstLLAddr)
        self.Label.move(5, 50)
        self.NDOpt_DstLLAddr_LLDstAddr_help = QtGui.QLineEdit(self.NDOpt_DstLLAddr)
        self.NDOpt_DstLLAddr_LLDstAddr_help.setInputMask('HH:HH:HH:HH:HH:HH')
        self.NDOpt_DstLLAddr_LLDstAddr = QtGui.QComboBox(self.NDOpt_DstLLAddr)
        self.NDOpt_DstLLAddr_LLDstAddr.setGeometry(QtCore.QRect(10, 75, 300, 30))
        self.NDOpt_DstLLAddr_LLDstAddr.setLineEdit(self.NDOpt_DstLLAddr_LLDstAddr_help)
        self.NDOpt_DstLLAddr_LLDstAddr.setEditable(True)
                # Prefix
        self.NDOpt_Prefix = QtGui.QWidget(self.NDOpt_tabWidget)
        self.NDOpt_tabWidget.addTab(self.NDOpt_Prefix, "Prefix")
        self.NDOpt_Prefix_Add = QtGui.QCheckBox("Add", self.NDOpt_Prefix)
        self.NDOpt_Prefix_Add.move(10, 10)
        self.Label = QtGui.QLabel("Prefix:", self.NDOpt_Prefix)
        self.Label.move(5, 50)
        self.Label_2 = QtGui.QLabel("Prefix lenght:", self.NDOpt_Prefix)
        self.Label_2.move(205, 50)
        self.NDOpt_Prefix_Prefix = QtGui.QLineEdit(self.NDOpt_Prefix)
        self.NDOpt_Prefix_Prefix.setGeometry(QtCore.QRect(10, 75, 150, 30))
        self.NDOpt_Prefix_PrefixLen = QtGui.QLineEdit(self.NDOpt_Prefix)
        self.NDOpt_Prefix_PrefixLen.setGeometry(QtCore.QRect(210, 75, 60, 30)) 
        self.NDOpt_Prefix_PrefixLen.setInputMask('999')
        self.connect(self.NDOpt_Prefix_PrefixLen, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_7)
        self.NDOpt_Prefix_LFlag = QtGui.QCheckBox("on-link - flag", self.NDOpt_Prefix)
        self.NDOpt_Prefix_LFlag.move(10, 115)
        self.NDOpt_Prefix_AFlag = QtGui.QCheckBox("autonomous address-configuration - flag", self.NDOpt_Prefix)
        self.NDOpt_Prefix_AFlag.move(10, 135)
        self.Label_3 = QtGui.QLabel("Valid Lifetime:", self.NDOpt_Prefix)
        self.Label_3.move(5, 170)
        self.Label_4 = QtGui.QLabel("Preferred Lifetime:", self.NDOpt_Prefix)
        self.Label_4.move(205, 170)
        self.NDOpt_Prefix_ValidL = QtGui.QLineEdit(self.NDOpt_Prefix)
        self.NDOpt_Prefix_ValidL.setGeometry(QtCore.QRect(10, 195, 100, 30))
        self.NDOpt_Prefix_ValidL.setInputMask('9999999999')
        self.NDOpt_Prefix_PreferredL = QtGui.QLineEdit(self.NDOpt_Prefix)
        self.NDOpt_Prefix_PreferredL.setGeometry(QtCore.QRect(210, 195, 100, 30)) 
        self.NDOpt_Prefix_PreferredL.setInputMask('9999999999')
        self.connect(self.NDOpt_Prefix_PreferredL, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32)
        self.connect(self.NDOpt_Prefix_ValidL, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32)
                # Redirected Header
        self.NDOpt_Redirect = QtGui.QWidget(self.NDOpt_tabWidget)
        self.NDOpt_tabWidget.addTab(self.NDOpt_Redirect, "Redirected")
        self.NDOpt_Redirect_Add = QtGui.QCheckBox("Add", self.NDOpt_Redirect)
        self.NDOpt_Redirect_Add.move(10, 10)
        self.Label = QtGui.QLabel("Capture File:", self.NDOpt_Redirect)
        self.Label.move(5, 50)
        self.Label_2 = QtGui.QLabel("Packet No.:", self.NDOpt_Redirect)
        self.Label_2.move(405, 50)
        self.NDOpt_Redirect_PacketFile = QtGui.QLineEdit(self.Payload['Capture File'], self.NDOpt_Redirect)
        self.NDOpt_Redirect_PacketFile.setGeometry(QtCore.QRect(10, 75, 301, 30))
        self.NDOpt_Redirect_PacketNo = QtGui.QLineEdit(self.Payload['Packet No.'], self.NDOpt_Redirect)
        self.NDOpt_Redirect_PacketNo.setGeometry(QtCore.QRect(410, 75, 50, 30))
        self.NDOpt_Redirect_pushButton = QtGui.QPushButton("Search...", self.NDOpt_Redirect)
        self.NDOpt_Redirect_pushButton.move(310, 76)
        self.connect(self.NDOpt_Redirect_pushButton, QtCore.SIGNAL('clicked(bool)'), self.ask_for_filename)
                # MTU
        self.NDOpt_MTU = QtGui.QWidget(self.NDOpt_tabWidget)
        self.NDOpt_tabWidget.addTab(self.NDOpt_MTU, "MTU")
        self.NDOpt_MTU_Add = QtGui.QCheckBox("Add", self.NDOpt_MTU)
        self.NDOpt_MTU_Add.move(10, 10)
        self.Label = QtGui.QLabel("MTU:", self.NDOpt_MTU)
        self.Label.move(5, 50)
        self.NDOpt_MTU_MTU = QtGui.QLineEdit(str(self.NDOpt['MTU']), self.NDOpt_MTU)
        self.NDOpt_MTU_MTU.setInputMask('9999999999')
        self.NDOpt_MTU_MTU.setGeometry(QtCore.QRect(10, 75, 100, 30))
        self.connect(self.NDOpt_MTU_MTU, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32) 

                # Source Address List
        self.NDOpt_SrcAddrList = QtGui.QWidget(self.NDOpt_tabWidget)
        self.NDOpt_tabWidget.addTab(self.NDOpt_SrcAddrList, "Source Address List")
        self.NDOpt_SrcAddrList_Add = QtGui.QCheckBox("Add", self.NDOpt_SrcAddrList)
        self.NDOpt_SrcAddrList_Add.move(10, 10)
        self.NDOpt_SrcAddrList_Label = QtGui.QLabel("Source Address List:", self.NDOpt_SrcAddrList)
        self.NDOpt_SrcAddrList_Label.move(width/2 - 160, 35)
        self.NDOpt_SrcAddrList_AddrArray = QtGui.QTableWidget(0, 1, self.NDOpt_SrcAddrList)
        self.NDOpt_SrcAddrList_AddrArray.setHorizontalHeaderLabels(["Source Addresses"])
        self.NDOpt_SrcAddrList_AddrArray.setColumnWidth(0,301)
        self.NDOpt_SrcAddrList_AddrArray.setGeometry(QtCore.QRect(width/2 - 150, 65, 300, height-200))
        self.NDOpt_SrcAddrList_Address = QtGui.QLineEdit(self.NDOpt_SrcAddrList)
        self.NDOpt_SrcAddrList_Address.setGeometry(QtCore.QRect(width/2 - 150, height-120, 300, 31))
        self.NDOpt_SrcAddrList_AddButton = QtGui.QPushButton("Add",self.NDOpt_SrcAddrList)
        self.NDOpt_SrcAddrList_AddButton.move(width/2 + 170, height-120)
        self.NDOpt_SrcAddrList_DeleteButton = QtGui.QPushButton("Delete",self.NDOpt_SrcAddrList)
        self.NDOpt_SrcAddrList_DeleteButton.move(width/2 + 170, height-155)
        self.connect(self.NDOpt_SrcAddrList_AddButton, QtCore.SIGNAL('clicked()'), self.AddIP)
        self.connect(self.NDOpt_SrcAddrList_DeleteButton, QtCore.SIGNAL('clicked()'), self.DeleteIP)

                # Target Address List
        self.NDOpt_TgtAddrList = QtGui.QWidget(self.NDOpt_tabWidget)
        self.NDOpt_tabWidget.addTab(self.NDOpt_TgtAddrList, "Target Address List")
        self.NDOpt_TgtAddrList_Add = QtGui.QCheckBox("Add", self.NDOpt_TgtAddrList)
        self.NDOpt_TgtAddrList_Add.move(10, 10)
        self.NDOpt_TgtAddrList_Label = QtGui.QLabel("Target Address List:", self.NDOpt_TgtAddrList)
        self.NDOpt_TgtAddrList_Label.move(width/2 - 160, 35)
        self.NDOpt_TgtAddrList_AddrArray = QtGui.QTableWidget(0, 1, self.NDOpt_TgtAddrList)
        self.NDOpt_TgtAddrList_AddrArray.setHorizontalHeaderLabels(["Target Addresses"])
        self.NDOpt_TgtAddrList_AddrArray.setColumnWidth(0,301)
        self.NDOpt_TgtAddrList_AddrArray.setGeometry(QtCore.QRect(width/2 - 150, 65, 300, height-200))
        self.NDOpt_TgtAddrList_Address = QtGui.QLineEdit(self.NDOpt_TgtAddrList)
        self.NDOpt_TgtAddrList_Address.setGeometry(QtCore.QRect(width/2 - 150, height-120, 300, 31))
        self.NDOpt_TgtAddrList_AddButton = QtGui.QPushButton("Add",self.NDOpt_TgtAddrList)
        self.NDOpt_TgtAddrList_AddButton.move(width/2 + 170, height-120)
        self.NDOpt_TgtAddrList_DeleteButton = QtGui.QPushButton("Delete",self.NDOpt_TgtAddrList)
        self.NDOpt_TgtAddrList_DeleteButton.move(width/2 + 170, height-155)
        self.connect(self.NDOpt_TgtAddrList_AddButton, QtCore.SIGNAL('clicked()'), self.AddIP)
        self.connect(self.NDOpt_TgtAddrList_DeleteButton, QtCore.SIGNAL('clicked()'), self.DeleteIP)    

        self.OKButton = QtGui.QPushButton("OK",self)
        self.OKButton.move(width/2 - 50, height - 35)
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.ready)
        
        ## get SourceLinkLayerAddresses, add them to the drop-down list
        iflist = get_if_list()
        i = len(iflist)
        self.NDOpt_SrcLLAddr_LLSrcAddr.addItem('')
        for d in range(0, i):
            self.NDOpt_SrcLLAddr_LLSrcAddr.addItem(get_if_hwaddr(iflist[d]))

        self.show()

        if self.NDOpt['Option'] & 1: self.NDOpt_SrcLLAddr_Add.setChecked(True)
        else: self.NDOpt_SrcLLAddr_Add.setChecked(False)
        if self.NDOpt['Option'] & 2: self.NDOpt_DstLLAddr_Add.setChecked(True)
        else: self.NDOpt_DstLLAddr_Add.setChecked(False)
        if self.NDOpt['Option'] & 4: self.NDOpt_Prefix_Add.setChecked(True)
        else: self.NDOpt_Prefix_Add.setChecked(False)
        if self.NDOpt['Option'] & 8: self.NDOpt_Redirect_Add.setChecked(True)
        else: self.NDOpt_Redirect_Add.setChecked(False)
        if self.NDOpt['Option'] & 16: self.NDOpt_MTU_Add.setChecked(True)
        else: self.NDOpt_MTU_Add.setChecked(False)
        if self.NDOpt['Option'] & 32: self.NDOpt_SrcAddrList_Add.setChecked(True)
        else: self.NDOpt_SrcAddrList_Add.setChecked(False)
        if self.NDOpt['Option'] & 64: self.NDOpt_TgtAddrList_Add.setChecked(True)
        else: self.NDOpt_TgtAddrList_Add.setChecked(False)
        self.NDOpt_SrcLLAddr_LLSrcAddr.setEditText(str(self.NDOpt['ND_SrcLLAddr']))
        self.NDOpt_DstLLAddr_LLDstAddr.setEditText(str(self.NDOpt['ND_DstLLAddr']))
        self.NDOpt_Prefix_Prefix.setText(self.NDOpt['Prefix'])
        self.NDOpt_Prefix_PrefixLen.setText(self.NDOpt['Prefixlen'])
        self.NDOpt_Prefix_LFlag.setChecked(self.NDOpt['L'])
        self.NDOpt_Prefix_AFlag.setChecked(self.NDOpt['A'])
        self.NDOpt_Prefix_ValidL.setText(self.NDOpt['ValidL'])
        self.NDOpt_Prefix_PreferredL.setText(self.NDOpt['PreferredL'])
        i = len(self.NDOpt['SrcAddrList'])
        for d in range(i):
            self.NDOpt_SrcAddrList_AddrArray.insertRow(d)
            t1 = QtGui.QTableWidgetItem(self.NDOpt['SrcAddrList'][d])
            self.NDOpt_SrcAddrList_AddrArray.setItem(d, 0, t1)
        i = len(self.NDOpt['TgtAddrList'])
        for d in range(i):
            self.NDOpt_TgtAddrList_AddrArray.insertRow(d)
            t1 = QtGui.QTableWidgetItem(self.NDOpt['TgtAddrList'][d])
            self.NDOpt_TgtAddrList_AddrArray.setItem(d, 0, t1)


    def AddIP(self):
        """This funcion adds an IPv6 address from the adress field into the address array. (Source and Target Address List)
"""
        if self.NDOpt_tabWidget.tabText(self.NDOpt_tabWidget.currentIndex()) == "Source Address List":
            numRows = self.NDOpt_SrcAddrList_AddrArray.rowCount()
            if numRows < 16:
                self.NDOpt_SrcAddrList_AddrArray.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.NDOpt_SrcAddrList_Address.text())
                self.NDOpt_SrcAddrList_AddrArray.setItem(numRows, 0, t1)
            else:
                self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")
        elif self.NDOpt_tabWidget.tabText(self.NDOpt_tabWidget.currentIndex()) == "Target Address List":
            numRows = self.NDOpt_TgtAddrList_AddrArray.rowCount()
            if numRows < 16:
                self.NDOpt_TgtAddrList_AddrArray.insertRow(numRows)
                t1 = QtGui.QTableWidgetItem(self.NDOpt_TgtAddrList_Address.text())
                self.NDOpt_TgtAddrList_AddrArray.setItem(numRows, 0, t1)
            else:
                self.err_msg = QtGui.QMessageBox.information(None, "Info!", "More addresses are not possible!")


    def DeleteIP(self):
        """A marked IPv6 address from the array can be deleted with this function. (Source and Target Address List)
"""
        if self.NDOpt_tabWidget.tabText(self.NDOpt_tabWidget.currentIndex()) == "Source Address List":
            Row = self.NDOpt_SrcAddrList_AddrArray.currentRow()
            if Row >= 0:
                self.NDOpt_SrcAddrList_AddrArray.removeRow(Row)
        elif self.NDOpt_tabWidget.tabText(self.NDOpt_tabWidget.currentIndex()) == "Target Address List":
            Row = self.NDOpt_TgtAddrList_AddrArray.currentRow()
            if Row >= 0:
                self.NDOpt_TgtAddrList_AddrArray.removeRow(Row)

    def slotMax2_32(self):
        """This function sets the maximum Value of a Line Edit Widget to 4294967295 (2^32-1).
"""
        if self.NDOpt_MTU_MTU.text() != '' and int(self.NDOpt_MTU_MTU.text()) >= 4294967296:
            self.NDOpt_MTU_MTU.setText('4294967295')
        if self.NDOpt_Prefix_ValidL.text() != '' and int(self.NDOpt_Prefix_ValidL.text()) >= 4294967296:
            self.NDOpt_Prefix_ValidL.setText('4294967295')
        if self.NDOpt_Prefix_PreferredL.text() != '' and int(self.NDOpt_Prefix_PreferredL.text()) >= 4294967296:
            self.NDOpt_Prefix_PreferredL.setText('4294967295')

    def slotMax2_7(self):
        """This function sets the maximum Value of a Line Edit Widget to 128 (2^7).
        """
        if self.NDOpt_Prefix_PrefixLen.text() != '' and int(self.NDOpt_Prefix_PrefixLen.text()) >= 129:
            self.NDOpt_Prefix_PrefixLen.setText('128')


    def ask_for_filename(self):
        """It opens a Dialog window where you can choose the pcap path for ICMP-ND-Redirect.
"""
        self.fileDialog = QtGui.QFileDialog.getOpenFileName(self,"FileDialog")
        self.NDOpt_Redirect_PacketFile.setText(self.fileDialog)

    def ready(self):
        """This function close the Neighbor Discovery Options window and save the information.
"""
        self.NDOpt['Option'] = 0
        if self.NDOpt_SrcLLAddr_Add.isChecked(): self.NDOpt['Option'] += 1
        if self.NDOpt_DstLLAddr_Add.isChecked(): self.NDOpt['Option'] += 2
        if self.NDOpt_Prefix_Add.isChecked(): self.NDOpt['Option'] += 4
        if self.NDOpt_Redirect_Add.isChecked(): self.NDOpt['Option'] += 8
        if self.NDOpt_MTU_Add.isChecked(): self.NDOpt['Option'] += 16
        if self.NDOpt_SrcAddrList_Add.isChecked(): self.NDOpt['Option'] += 32
        if self.NDOpt_TgtAddrList_Add.isChecked(): self.NDOpt['Option'] += 64
        self.NDOpt['ND_SrcLLAddr'] = self.NDOpt_SrcLLAddr_LLSrcAddr.currentText()
        if self.NDOpt['ND_SrcLLAddr'] == ':::::': self.NDOpt['ND_SrcLLAddr'] = '00:00:00:00:00:00'
        self.NDOpt['ND_DstLLAddr'] = self.NDOpt_DstLLAddr_LLDstAddr.currentText()
        if self.NDOpt['ND_DstLLAddr'] == ':::::': self.NDOpt['ND_DstLLAddr'] = 'FF:FF:FF:FF:FF:FF'
        if ((self.NDOpt_Prefix_Prefix.text() == '') or (self.NDOpt_Prefix_PrefixLen.text() == '')) and self.NDOpt_Prefix_Add.isChecked():
             self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Prefix and Prefix length are requiered!\n(Default: Prefix = 'fd00:141:64:1::'; Prefixlength = 64)")
        if self.NDOpt_Prefix_Prefix.text() == '': self.NDOpt_Prefix_Prefix.setText('fd00:141:64:1::')
        if self.NDOpt_Prefix_PrefixLen.text() == '': self.NDOpt_Prefix_PrefixLen.setText('64')
        self.NDOpt['Prefix'] = self.NDOpt_Prefix_Prefix.text()
        self.NDOpt['Prefixlen'] = self.NDOpt_Prefix_PrefixLen.text()
        self.NDOpt['L'] = self.NDOpt_Prefix_LFlag.isChecked()
        self.NDOpt['A'] = self.NDOpt_Prefix_AFlag.isChecked()
        if self.NDOpt_Prefix_ValidL.text() == '': self.NDOpt_Prefix_Prefix.setText('4294967295')
        if self.NDOpt_Prefix_PreferredL.text() == '': self.NDOpt_Prefix_PrefixLen.setText('4294967295')
        self.NDOpt['ValidL'] = self.NDOpt_Prefix_ValidL.text()
        self.NDOpt['PreferredL'] = self.NDOpt_Prefix_PreferredL.text()
        self.Payload['Capture File'] = self.NDOpt_Redirect_PacketFile.text()
        self.Payload['Packet No.'] = self.NDOpt_Redirect_PacketNo.text()
        if (self.Payload['Capture File'] == '' or self.Payload['Packet No.'] == '') and self.NDOpt_Redirect_Add.isChecked():
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Pcap-File and Packet No. are requiered\nto create a valid package!")
            return
        if self.NDOpt_MTU_MTU.text() == '': self.NDOpt_MTU_MTU.setText('1280')
        self.NDOpt['MTU'] = self.NDOpt_MTU_MTU.text()
        self.addresses=[]
        i = self.NDOpt_SrcAddrList_AddrArray.rowCount()
        for d in range(i):
            self.addresses.append([])
            self.addresses[d] = str(QtGui.QTableWidgetItem.text(self.NDOpt_SrcAddrList_AddrArray.item(d, 0)))
        self.NDOpt['SrcAddrList'] = self.addresses
        self.addresses=[]
        i = self.NDOpt_TgtAddrList_AddrArray.rowCount()
        for d in range(i):
            self.addresses.append([])
            self.addresses[d] = str(QtGui.QTableWidgetItem.text(self.NDOpt_TgtAddrList_AddrArray.item(d, 0)))
        self.NDOpt['TgtAddrList'] = self.addresses

        self.accept()

class Payload(QtGui.QDialog):
    """The ``Payload`` class is necessary to load a pcap path and type a packet number. 

    :param PayloadFile: comprise the pcap path and packet number
    :type PayloadFile: Capture File, Packet No.

"""
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
        self.connect(self.OKButton, QtCore.SIGNAL('clicked()'), self.ready)
        
        self.show()

    def ask_for_filename(self):
        """It opens a Dialog window where you can choose the pcap path.
"""
        self.fileDialog = QtGui.QFileDialog.getOpenFileName(self,"FileDialog")
        self.PacketFile.setText(self.fileDialog)
 
    def ready(self):
        """This function close the payload window and save the information.
"""
        self.PayloadFile['Capture File'] = self.PacketFile.text()
        self.PayloadFile['Packet No.'] = self.PacketNo.text()
        
        self.accept()

class RoundTrip(QtGui.QDialog):
    """This class opens a tool that messure the round trip time of one or more pings and allocate mean round trip time.

    :param DstAdd: an array with destination addresses that fill a combo box

    You can choose a destination address and a number of pings to messure the round trip time of the packets.
"""
    def __init__(self,DstAdd):
        QtGui.QDialog.__init__(self)
        self.setWindowTitle("Ping (Round-Trip Time)")
        self.resize(320, 180)
        self.Label = QtGui.QLabel("IPv6 Destination Address:", self)
        self.Label.move(5, 10)
        self.IPv6_DstAddr = QtGui.QComboBox(self)
        self.IPv6_DstAddr.setGeometry(QtCore.QRect(10, 35, 300, 30))
        self.IPv6_DstAddr.setEditable(True)
        self.Label_3 = QtGui.QLabel("Packet Count:", self)
        self.Label_3.move(5, 110)
        self.pktcount = QtGui.QLineEdit("3", self)
        self.pktcount.setGeometry(QtCore.QRect(125, 106, 60, 25))
        self.pktcount.setInputMask('9')
        

        ## init Dst Add
        
        i = len(DstAdd)
        for d in range(0, i):
            if DstAdd[d] != '::1' and DstAdd[d] != 'fe80::1':
                self.IPv6_DstAddr.addItem(DstAdd[d])

        self.PingButton = QtGui.QPushButton("Ping",self)
        self.PingButton.setGeometry(QtCore.QRect(50, 140, 98, 27))
        self.connect(self.PingButton, QtCore.SIGNAL('clicked()'), self.SendSniff)
        self.CloseButton = QtGui.QPushButton("Close",self)
        self.CloseButton.setGeometry(QtCore.QRect(152, 140, 98, 27))
        self.connect(self.CloseButton, QtCore.SIGNAL('clicked()'), self.Close)

        self.show()

    def SendSniff(self):
        """This function sniff the packet transfer and analyse the request and answer packets.
        It also open another thread to send the pings::

            thread.start_new_thread(self.Ping, (self.pktcount.text(), ))
"""
        if self.pktcount.text() == ('' or '0'):
            self.pktcount.setText('5')
        thread.start_new_thread(self.Ping, (self.pktcount.text(), ))
        ans = sniff(filter=('ether proto 0x86dd'), timeout=int(self.pktcount.text()))
        request = []
        reply = []
        for packet in ans:
            if packet.type == 0x86dd:
                if packet[IPv6].type == 128:
                    request.append(packet)
                if packet[IPv6].type == 129:
                    reply.append(packet)
        if reply == None:
            info = 'Host is down'
        else:
            if len(request) == len(reply) and len(reply) == int(self.pktcount.text()):
                d = 0
                timediff = []
                timediffstr = ''
                while d < len(request):
                    timediff.append((reply[d].sent_time - request[d].time)*1000)
                    timediffstr = timediffstr + str((reply[d].sent_time - request[d].time)*1000)+' ms\n'
                    d += 1
                info = 'The Round-Trip Time of the individual pings are: \n'+timediffstr+'\nThe mean Time is '+ str(sum(timediff)/int(self.pktcount.text())) +' ms.'
            else:
                info = 'One or more replies are missing or Scapy cannot send all Packets!'
        self.msg = QtGui.QMessageBox.information(None, "Result!", info)

    def Ping(self, pktcount):  
        """This thread sends the Echo Request messages in a second thread.

        :param pktcount: number of pings
        :type pktcount: int
"""
        waittime = .5  
        ping = IPv6(dst=str(self.IPv6_DstAddr.currentText()))/ICMPv6EchoRequest()     
        ans = srloop(ping, timeout = waittime, count=int(pktcount))

    def Close(self):
        """This function close the Round Trip Time tool.
"""
        self.close()

