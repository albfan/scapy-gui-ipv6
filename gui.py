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
import shelve
from PyQt4 import QtCore, QtGui, Qt
from scapy.all import *
import program_background
import program_help_gui

class Main(QtGui.QMainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        self.setWindowTitle("Scapy GUI")
        self.setMinimumWidth(600)
        self.setMinimumHeight(370)
        width = 600     # min. 600
        height = 370     # min. 370
        if width < self.minimumWidth(): width = self.minimumWidth()
        if height < self.minimumHeight(): height = self.minimumHeight()
        self.resize(width, height)
        self.makeActions()
        self.makeMenu()

        self.IPv6DstList = QtCore.QStringList()
        self.IPv6 = program_background.IPv6Packet()

        # TabWidget
        self.tabWidget = QtGui.QTabWidget(self)
        self.tabWidget.setGeometry(QtCore.QRect(0, 30, width, height-70))

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
        self.IPv6_Label = QtGui.QLabel("Destination IPv6-address (or name):", self.tab_IPv6)
        self.IPv6_Label.move(5, 35)
        self.IPv6_Label_2 = QtGui.QLabel("Source IPv6-address:", self.tab_IPv6)
        self.IPv6_Label_2.move(5, 105)
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
        self.IPv6_Button_ExpertMode = QtGui.QCheckBox('Expert Mode', self.tab_IPv6)
        self.IPv6_Button_ExpertMode.move(5, 185)
        self.IPv6_ExpertMode = QtGui.QWidget(self.tab_IPv6)
        self.IPv6_ExpertMode.setGeometry(QtCore.QRect(400, 45, 200, 225))
        self.IPv6_ExpertMode.setVisible(False)
        self.IPv6_Label_3 = QtGui.QLabel("Hop Limit:", self.IPv6_ExpertMode)
        self.IPv6_Label_3.move(5, 5)
        self.IPv6_HopLimit = QtGui.QLineEdit("64",self.IPv6_ExpertMode)
        self.IPv6_HopLimit.setInputMask('999')
        self.IPv6_HopLimit.setGeometry(QtCore.QRect(10, 30, 60, 30))
        self.IPv6_Label_4 = QtGui.QLabel("Traffic Class:", self.IPv6_ExpertMode)
        self.IPv6_Label_4.move(5, 75)
        self.IPv6_TrafficClass = QtGui.QLineEdit("0",self.IPv6_ExpertMode)
        self.IPv6_TrafficClass.setInputMask('999')
        self.IPv6_TrafficClass.setGeometry(QtCore.QRect(10, 100, 60, 30))  
        self.IPv6_Label_5 = QtGui.QLabel("Flow Label:", self.IPv6_ExpertMode)
        self.IPv6_Label_5.move(5, 145)
        self.IPv6_FlowLabel = QtGui.QLineEdit("0",self.IPv6_ExpertMode)
        self.IPv6_FlowLabel.setInputMask('9999999')
        self.IPv6_FlowLabel.setGeometry(QtCore.QRect(10, 170, 60, 30))
        self.connect(self.IPv6_HopLimit, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.connect(self.IPv6_TrafficClass, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.connect(self.IPv6_FlowLabel, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_20)
        self.connect(self.IPv6_Button_ExpertMode, QtCore.SIGNAL('clicked(bool)'), self.slotExpertMode)

            # Third Tab - Extension Header
        self.tab_ExtHdr = QtGui.QWidget(self.tabWidget)
        self.tabWidget.addTab(self.tab_ExtHdr, "Extension Header")
        self.ExtHdr_tableWidget = QtGui.QTableWidget(0, 1, self.tab_ExtHdr)
        self.ExtHdr_tableWidget.setHorizontalHeaderLabels(["Extension Header"])
        self.ExtHdr_tableWidget.setColumnWidth(0, 251)
        self.ExtHdr_tableWidget.setGeometry(QtCore.QRect(width/2 - 170, 10, 250, height - 120 ))
        self.ExtHdr_AddButton = QtGui.QPushButton("Add", self.tab_ExtHdr)
        self.ExtHdr_AddButton.move(width/2 + 120, 50)
        self.ExtHdr_EditButton = QtGui.QPushButton("Edit", self.tab_ExtHdr)
        self.ExtHdr_EditButton.move(width/2 + 120, 80)
        self.ExtHdr_DeleteButton = QtGui.QPushButton("Delete", self.tab_ExtHdr)
        self.ExtHdr_DeleteButton.move(width/2 + 120, 110)
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
        self.tab_NH_ICMP = QtGui.QWidget(self.tab_NextHeader)
        self.tab_NH_ICMP.setGeometry(QtCore.QRect(0, 50, width, height - 120))
        self.tab_NH_ICMP.setVisible(True)
        self.ICMP_Type = QtGui.QComboBox(self.tab_NextHeader)
        self.ICMP_Type.addItem('1 - Destination Unreachable')
        self.ICMP_Type.addItem('2 - Packet Too Big')
        self.ICMP_Type.addItem('3 - Time Exceeded')
        self.ICMP_Type.addItem('4 - Parameter Problem')
        self.ICMP_Type.addItem('128 - Echo Request')
        self.ICMP_Type.addItem('129 - Echo Reply')
        self.ICMP_Type.addItem('130 - Multicast Listener Query')
        self.ICMP_Type.addItem('131 - Multicast Listener Report')
        self.ICMP_Type.addItem('132 - Multicast Listener Done')
        self.ICMP_Type.addItem('133 - Router Solicitation')
        self.ICMP_Type.addItem('134 - Router Advertisement')
        self.ICMP_Type.addItem('135 - Neighbor Solicitation')
        self.ICMP_Type.addItem('136 - Neighbor Advertisement')
        self.ICMP_Type.addItem('137 - Redirect')
        self.ICMP_Type.addItem('141 - Inverse Neighbor Discovery Solicitation')
        self.ICMP_Type.addItem('142 - Inverse Neighbor Discovery Advertisement')
        self.ICMP_Type.addItem('other ICMP Type')
        self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('128 - Echo Request'))
        self.ICMP_Type.move(200, 20)
        self.connect(self.ICMP_Type, QtCore.SIGNAL('activated(int)'), self.ICMPConf)

                    # Destination Unreachable

        self.NH_ICMP_DestUnreach = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_DestUnreach.setVisible(False) 
        self.Label = QtGui.QLabel("Code:", self.NH_ICMP_DestUnreach)
        self.Label.move(5, 10)
        self.NH_ICMP_DestUnreach_Code = QtGui.QLineEdit("0",self.NH_ICMP_DestUnreach)
        self.NH_ICMP_DestUnreach_Code.setInputMask('999')
        self.NH_ICMP_DestUnreach_Code.setGeometry(QtCore.QRect(10, 35, 60, 30))
        self.Label_2 = QtGui.QLabel("Define a packet which will be used as payload. (necessary)", self.NH_ICMP_DestUnreach)
        self.Label_2.setGeometry(QtCore.QRect(5, 80, 400, 30))
        self.Label_3 = QtGui.QLabel("Capture File:", self.NH_ICMP_DestUnreach)
        self.Label_3.move(5, 120)
        self.Label_4 = QtGui.QLabel("Packet No.:", self.NH_ICMP_DestUnreach)
        self.Label_4.move(405, 120)
        self.NH_ICMP_DestUnreach_PacketFile = QtGui.QLineEdit(self.IPv6.Payload['Capture File'], self.NH_ICMP_DestUnreach)
        self.NH_ICMP_DestUnreach_PacketFile.setGeometry(QtCore.QRect(10, 140, 301, 30))
        self.NH_ICMP_DestUnreach_PacketNo = QtGui.QLineEdit(self.IPv6.Payload['Packet No.'], self.NH_ICMP_DestUnreach)
        self.NH_ICMP_DestUnreach_PacketNo.setGeometry(QtCore.QRect(410, 140, 50, 30))
        self.NH_ICMP_DestUnreach_pushButton = QtGui.QPushButton("Search...", self.NH_ICMP_DestUnreach)
        self.NH_ICMP_DestUnreach_pushButton.move(310, 141)
        self.connect(self.NH_ICMP_DestUnreach_pushButton, QtCore.SIGNAL('clicked(bool)'), self.ask_for_filename)
        self.connect(self.NH_ICMP_DestUnreach_Code, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        
                    # Packet Too Big
        
        self.NH_ICMP_PTB = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_PTB.setVisible(False)
        self.Label = QtGui.QLabel("Code:", self.NH_ICMP_PTB)
        self.Label.move(5, 10)
        self.Label_2 = QtGui.QLabel("MTU:", self.NH_ICMP_PTB)
        self.Label_2.move(205, 10)
        self.NH_ICMP_PTB_Code = QtGui.QLineEdit("0",self.NH_ICMP_PTB)
        self.NH_ICMP_PTB_Code.setGeometry(QtCore.QRect(10, 35, 60, 30))
        self.NH_ICMP_PTB_Code.setInputMask('999')
        self.NH_ICMP_PTB_MTU = QtGui.QLineEdit("1280", self.NH_ICMP_PTB)
        self.NH_ICMP_PTB_MTU.setInputMask('9999999999')
        self.NH_ICMP_PTB_MTU.setGeometry(QtCore.QRect(210, 35, 100, 30))
        self.connect(self.NH_ICMP_PTB_MTU, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32)
        self.Label_3 = QtGui.QLabel("Define a packet which will be used as payload. (necessary)", self.NH_ICMP_PTB)
        self.Label_3.setGeometry(QtCore.QRect(5, 80, 400, 30))
        self.Label_4 = QtGui.QLabel("Capture File:", self.NH_ICMP_PTB)
        self.Label_4.move(5, 120)
        self.Label_5 = QtGui.QLabel("Packet No.:", self.NH_ICMP_PTB)
        self.Label_5.move(405, 120)
        self.NH_ICMP_PTB_PacketFile = QtGui.QLineEdit(self.IPv6.Payload['Capture File'], self.NH_ICMP_PTB)
        self.NH_ICMP_PTB_PacketFile.setGeometry(QtCore.QRect(10, 140, 301, 30))
        self.NH_ICMP_PTB_PacketNo = QtGui.QLineEdit(self.IPv6.Payload['Packet No.'], self.NH_ICMP_PTB)
        self.NH_ICMP_PTB_PacketNo.setGeometry(QtCore.QRect(410, 140, 50, 30))
        self.NH_ICMP_PTB_pushButton = QtGui.QPushButton("Search...", self.NH_ICMP_PTB)
        self.NH_ICMP_PTB_pushButton.move(310, 141)
        self.connect(self.NH_ICMP_PTB_pushButton, QtCore.SIGNAL('clicked(bool)'), self.ask_for_filename)
        self.connect(self.NH_ICMP_PTB_Code, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)

                    # Time Exceeded

        self.NH_ICMP_TimeExceeded = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_TimeExceeded.setVisible(False) 
        self.Label = QtGui.QLabel("Code:", self.NH_ICMP_TimeExceeded)
        self.Label.move(5, 10)
        self.NH_ICMP_TimeExceeded_Code = QtGui.QLineEdit("0",self.NH_ICMP_TimeExceeded)
        self.NH_ICMP_TimeExceeded_Code.setGeometry(QtCore.QRect(10, 35, 60, 30))
        self.NH_ICMP_TimeExceeded_Code.setInputMask('999')
        self.Label_2 = QtGui.QLabel("Define a packet which will be used as payload. (necessary)", self.NH_ICMP_TimeExceeded)
        self.Label_2.setGeometry(QtCore.QRect(5, 80, 400, 30))
        self.Label_3 = QtGui.QLabel("Capture File:", self.NH_ICMP_TimeExceeded)
        self.Label_3.move(5, 120)
        self.Label_4 = QtGui.QLabel("Packet No.:", self.NH_ICMP_TimeExceeded)
        self.Label_4.move(405, 120)
        self.NH_ICMP_TimeExceeded_PacketFile = QtGui.QLineEdit(self.IPv6.Payload['Capture File'], self.NH_ICMP_TimeExceeded)
        self.NH_ICMP_TimeExceeded_PacketFile.setGeometry(QtCore.QRect(10, 140, 301, 30))
        self.NH_ICMP_TimeExceeded_PacketNo = QtGui.QLineEdit(self.IPv6.Payload['Packet No.'], self.NH_ICMP_TimeExceeded)
        self.NH_ICMP_TimeExceeded_PacketNo.setGeometry(QtCore.QRect(410, 140, 50, 30))
        self.NH_ICMP_TimeExceeded_pushButton = QtGui.QPushButton("Search...", self.NH_ICMP_TimeExceeded)
        self.NH_ICMP_TimeExceeded_pushButton.move(310, 141)
        self.connect(self.NH_ICMP_TimeExceeded_pushButton, QtCore.SIGNAL('clicked(bool)'), self.ask_for_filename)
        self.connect(self.NH_ICMP_TimeExceeded_Code, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)

                    # Parameter Problem

        self.NH_ICMP_ParamProblem = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_ParamProblem.setVisible(False) 
        self.Label = QtGui.QLabel("Code:", self.NH_ICMP_ParamProblem)
        self.Label.move(5, 10)
        self.Label_2 = QtGui.QLabel("Pointer:", self.NH_ICMP_ParamProblem)
        self.Label_2.move(205, 10)
        self.NH_ICMP_ParamProblem_Code = QtGui.QLineEdit("0",self.NH_ICMP_ParamProblem)
        self.NH_ICMP_ParamProblem_Code.setGeometry(QtCore.QRect(10, 35, 60, 30))
        self.NH_ICMP_ParamProblem_Code.setInputMask('999')
        self.NH_ICMP_ParamProblem_Pointer = QtGui.QLineEdit("6",self.NH_ICMP_ParamProblem)
        self.NH_ICMP_ParamProblem_Pointer.setGeometry(QtCore.QRect(210, 35, 100, 30)) 
        self.NH_ICMP_ParamProblem_Pointer.setText(self.IPv6.ICMP['Pointer'])
        self.NH_ICMP_ParamProblem_Pointer.setInputMask('9999999999')
        self.Label_3 = QtGui.QLabel("Define a packet which will be used as payload. (necessary)", self.NH_ICMP_ParamProblem)
        self.Label_3.setGeometry(QtCore.QRect(5, 80, 400, 30))
        self.Label_4 = QtGui.QLabel("Capture File:", self.NH_ICMP_ParamProblem)
        self.Label_4.move(5, 120)
        self.Label_5 = QtGui.QLabel("Packet No.:", self.NH_ICMP_ParamProblem)
        self.Label_5.move(405, 120)
        self.NH_ICMP_ParamProblem_PacketFile = QtGui.QLineEdit(self.IPv6.Payload['Capture File'], self.NH_ICMP_ParamProblem)
        self.NH_ICMP_ParamProblem_PacketFile.setGeometry(QtCore.QRect(10, 140, 301, 30))
        self.NH_ICMP_ParamProblem_PacketNo = QtGui.QLineEdit(self.IPv6.Payload['Packet No.'], self.NH_ICMP_ParamProblem)
        self.NH_ICMP_ParamProblem_PacketNo.setGeometry(QtCore.QRect(410, 140, 50, 30))
        self.NH_ICMP_ParamProblem_pushButton = QtGui.QPushButton("Search...", self.NH_ICMP_ParamProblem)
        self.NH_ICMP_ParamProblem_pushButton.move(310, 141)
        self.connect(self.NH_ICMP_ParamProblem_pushButton, QtCore.SIGNAL('clicked(bool)'), self.ask_for_filename)
        self.connect(self.NH_ICMP_ParamProblem_Code, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.connect(self.NH_ICMP_ParamProblem_Pointer, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_32)
        
                    # Echo Request

        self.NH_ICMP_Ping = QtGui.QWidget(self.tab_NH_ICMP)
        self.Label_3 = QtGui.QLabel("Message:", self.NH_ICMP_Ping)
        self.Label_3.move(5, 50)
        self.NH_ICMP_Ping_Message = QtGui.QTextEdit("", self.NH_ICMP_Ping)
        self.NH_ICMP_Ping_Message.setGeometry(QtCore.QRect(10, 70, 200, 50))
        
                    # Echo Reply

        self.NH_ICMP_EchoReply = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_EchoReply.setVisible(False)
        self.Label_3 = QtGui.QLabel("Message:", self.NH_ICMP_EchoReply)
        self.Label_3.move(5, 50)
        self.NH_ICMP_EchoReply_Message = QtGui.QTextEdit("", self.NH_ICMP_EchoReply)
        self.NH_ICMP_EchoReply_Message.setGeometry(QtCore.QRect(10, 70, 200, 50))

                    # Multicast Listener Query

        self.NH_ICMP_MultiQuery = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_MultiQuery.setVisible(False)
        self.Label = QtGui.QLabel("Maximum Response Delay:", self.NH_ICMP_MultiQuery)
        self.Label.move(5, 10)
        self.Label_2 = QtGui.QLabel("Multicast Listener Address:", self.NH_ICMP_MultiQuery)
        self.Label_2.move(5, 85)
        self.NH_ICMP_MultiQuery_MRD = QtGui.QLineEdit("10000",self.NH_ICMP_MultiQuery)
        self.NH_ICMP_MultiQuery_MRD.setGeometry(QtCore.QRect(10, 35, 60, 30))
        self.NH_ICMP_MultiQuery_MRD.setInputMask('99999')
        self.NH_ICMP_MultiQuery_MLAddr = QtGui.QComboBox(self.NH_ICMP_MultiQuery)
        self.NH_ICMP_MultiQuery_MLAddr.setGeometry(QtCore.QRect(10, 110, 300, 31))
        self.NH_ICMP_MultiQuery_MLAddr.setEditable(True)
        self.NH_ICMP_MultiQuery_MLAddr.setDuplicatesEnabled(True)
        self.NH_ICMP_MultiQuery_MLAddr.addItem('::')
        self.NH_ICMP_MultiQuery_MLAddr.addItem('ff01::1')
        self.NH_ICMP_MultiQuery_MLAddr.addItem('ff02::1')
        self.NH_ICMP_MultiQuery_MLAddr.addItem('ff02::2')
        self.connect(self.NH_ICMP_MultiQuery_MRD, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_16)

                    # Multicast Listener Report

        self.NH_ICMP_MultiReport = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_MultiReport.setVisible(False)
        self.Label = QtGui.QLabel("Multicast Listener Address:", self.NH_ICMP_MultiReport)
        self.Label.move(5, 10)
        self.NH_ICMP_MultiReport_MLAddr = QtGui.QComboBox(self.NH_ICMP_MultiReport)
        self.NH_ICMP_MultiReport_MLAddr.setGeometry(QtCore.QRect(10, 35, 300, 31))
        self.NH_ICMP_MultiReport_MLAddr.setEditable(True)
        self.NH_ICMP_MultiReport_MLAddr.setDuplicatesEnabled(True)
        self.NH_ICMP_MultiReport_MLAddr.addItem('::')
        self.NH_ICMP_MultiReport_MLAddr.addItem('ff01::1')
        self.NH_ICMP_MultiReport_MLAddr.addItem('ff02::1')
        self.NH_ICMP_MultiReport_MLAddr.addItem('ff02::2')

                    # Multicast Listener Done

        self.NH_ICMP_MultiDone = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_MultiDone.setVisible(False)
        self.Label = QtGui.QLabel("Multicast Listener Address:", self.NH_ICMP_MultiDone)
        self.Label.move(5, 10)
        self.NH_ICMP_MultiDone_MLAddr = QtGui.QComboBox(self.NH_ICMP_MultiDone)
        self.NH_ICMP_MultiDone_MLAddr.setGeometry(QtCore.QRect(10, 35, 300, 31))
        self.NH_ICMP_MultiDone_MLAddr.setEditable(True)
        self.NH_ICMP_MultiDone_MLAddr.setDuplicatesEnabled(True)
        self.NH_ICMP_MultiDone_MLAddr.addItem('::')
        self.NH_ICMP_MultiDone_MLAddr.addItem('ff01::1')
        self.NH_ICMP_MultiDone_MLAddr.addItem('ff02::1')
        self.NH_ICMP_MultiDone_MLAddr.addItem('ff02::2')

                    # Router Solicitation

        self.NH_ICMP_RouterSol = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_RouterSol.setVisible(False)
        self.NH_ICMP_RouterSol.setGeometry(QtCore.QRect(0, 0, width, height - 120))

        self.line = QtGui.QFrame(self.NH_ICMP_RouterSol)
        self.line.setGeometry(QtCore.QRect(5, 150, width - 15, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label = QtGui.QLabel("Option(optional):", self.NH_ICMP_RouterSol)
        self.Label.move(5, 160)
        self.NH_ICMP_RouterSol_Options = QtGui.QPushButton("Neighbor Discovery Options",self.NH_ICMP_RouterSol)
        self.NH_ICMP_RouterSol_Options.move(10, 180)
        self.connect(self.NH_ICMP_RouterSol_Options, QtCore.SIGNAL('clicked()'), self.slotNDOptHdr)

                    # Router Advertisement

        self.NH_ICMP_RouterAdv = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_RouterAdv.setVisible(False)
        self.NH_ICMP_RouterAdv.setGeometry(QtCore.QRect(0, 0, width, height - 120))
        self.Label = QtGui.QLabel("Cur Hop Limit:", self.NH_ICMP_RouterAdv)
        self.Label.move(5, 10)
        self.NH_ICMP_RouterAdv_CHLim = QtGui.QLineEdit(self.NH_ICMP_RouterAdv)
        self.NH_ICMP_RouterAdv_CHLim.setGeometry(QtCore.QRect(10, 35, 60, 30))
        self.NH_ICMP_RouterAdv_CHLim.setText(self.IPv6.RAconf['CHLim'])
        self.NH_ICMP_RouterAdv_CHLim.setInputMask('999')
        self.connect(self.NH_ICMP_RouterAdv_CHLim, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.Label_2 = QtGui.QLabel("Router Life Time:", self.NH_ICMP_RouterAdv)
        self.Label_2.move(145, 10)
        self.NH_ICMP_RouterAdv_RLTime = QtGui.QLineEdit(self.NH_ICMP_RouterAdv)
        self.NH_ICMP_RouterAdv_RLTime.setGeometry(QtCore.QRect(150, 35, 60, 30))
        self.NH_ICMP_RouterAdv_RLTime.setText(self.IPv6.RAconf['RLTime'])
        self.NH_ICMP_RouterAdv_RLTime.setInputMask('99999')
        self.connect(self.NH_ICMP_RouterAdv_RLTime, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_16)
        self.NH_ICMP_RouterAdv_MFlag = QtGui.QCheckBox("Managed address configuration - flag", self.NH_ICMP_RouterAdv)
        self.NH_ICMP_RouterAdv_MFlag.move(10, 80)
        self.NH_ICMP_RouterAdv_MFlag.setChecked(self.IPv6.RAconf['M'])
        self.NH_ICMP_RouterAdv_OFlag = QtGui.QCheckBox("Other configuration - flag", self.NH_ICMP_RouterAdv)
        self.NH_ICMP_RouterAdv_OFlag.move(10, 100)
        self.NH_ICMP_RouterAdv_OFlag.setChecked(self.IPv6.RAconf['O'])

        self.line = QtGui.QFrame(self.NH_ICMP_RouterAdv)
        self.line.setGeometry(QtCore.QRect(5, 150, width - 15, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label = QtGui.QLabel("Option(optional):", self.NH_ICMP_RouterAdv)
        self.Label.move(5, 160)
        self.NH_ICMP_RouterAdv_Options = QtGui.QPushButton("Neighbor Discovery Options",self.NH_ICMP_RouterAdv)
        self.NH_ICMP_RouterAdv_Options.move(10, 180)
        self.connect(self.NH_ICMP_RouterAdv_Options, QtCore.SIGNAL('clicked()'), self.slotNDOptHdr)

                    # Neighbor Solicitation
        
        self.NH_ICMP_NeighborSol = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_NeighborSol.setVisible(False)
        self.Label = QtGui.QLabel("Target IPv6 Address:", self.NH_ICMP_NeighborSol)
        self.Label.move(5, 10)
        self.NH_ICMP_NeighborSol_tgtAddr = QtGui.QComboBox(self.NH_ICMP_NeighborSol)
        self.NH_ICMP_NeighborSol_tgtAddr.setGeometry(QtCore.QRect(10, 35, 300, 30))
        self.NH_ICMP_NeighborSol_tgtAddr.setEditable(True)
        self.NH_ICMP_NeighborSol_tgtAddr.setEditText(self.IPv6.NSconf['NS_tgtAddr'])
        self.NH_ICMP_NeighborSol_tgtAddr.addItem('')
        self.NH_ICMP_NeighborSol_tgtAddr.addItem('ff01::1')
        self.NH_ICMP_NeighborSol_tgtAddr.addItem('ff02::1')
        self.NH_ICMP_NeighborSol_tgtAddr.addItem('ff80::1')

        self.line = QtGui.QFrame(self.NH_ICMP_NeighborSol)
        self.line.setGeometry(QtCore.QRect(5, 150, width - 15, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label = QtGui.QLabel("Option(optional):", self.NH_ICMP_NeighborSol)
        self.Label.move(5, 160)
        self.NH_ICMP_NeighborSol_Options = QtGui.QPushButton("Neighbor Discovery Options",self.NH_ICMP_NeighborSol)
        self.NH_ICMP_NeighborSol_Options.move(10, 180)
        self.connect(self.NH_ICMP_NeighborSol_Options, QtCore.SIGNAL('clicked()'), self.slotNDOptHdr)

                    # Neighbor Advertisement

        self.NH_ICMP_NeighborAdv = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_NeighborAdv.setVisible(False)
        self.Label = QtGui.QLabel("Target IPv6 Address:", self.NH_ICMP_NeighborAdv)
        self.Label.move(5, 10)
        self.NH_ICMP_NeighborAdv_tgtAddr = QtGui.QComboBox(self.NH_ICMP_NeighborAdv)
        self.NH_ICMP_NeighborAdv_tgtAddr.setGeometry(QtCore.QRect(10, 35, 300, 30))
        self.NH_ICMP_NeighborAdv_tgtAddr.setEditable(True)
        self.NH_ICMP_NeighborAdv_tgtAddr.addItem('')
        self.NH_ICMP_NeighborAdv_tgtAddr.addItem('ff01::1')
        self.NH_ICMP_NeighborAdv_tgtAddr.addItem('ff02::1')
        self.NH_ICMP_NeighborAdv_tgtAddr.addItem('ff80::1')
        self.NH_ICMP_NeighborAdv_RFlag = QtGui.QCheckBox("Router - flag", self.NH_ICMP_NeighborAdv)
        self.NH_ICMP_NeighborAdv_RFlag.move(10, 80)
        self.NH_ICMP_NeighborAdv_RFlag.setChecked(self.IPv6.NAconf['R'])
        self.NH_ICMP_NeighborAdv_SFlag = QtGui.QCheckBox("Solicited - flag", self.NH_ICMP_NeighborAdv)
        self.NH_ICMP_NeighborAdv_SFlag.move(10, 100)
        self.NH_ICMP_NeighborAdv_SFlag.setChecked(self.IPv6.NAconf['S'])
        self.NH_ICMP_NeighborAdv_OFlag = QtGui.QCheckBox("Override - flag", self.NH_ICMP_NeighborAdv)
        self.NH_ICMP_NeighborAdv_OFlag.move(10, 120)
        self.NH_ICMP_NeighborAdv_OFlag.setChecked(self.IPv6.NAconf['O'])

        self.line = QtGui.QFrame(self.NH_ICMP_NeighborAdv)
        self.line.setGeometry(QtCore.QRect(5, 150, width - 15, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label = QtGui.QLabel("Option(optional):", self.NH_ICMP_NeighborAdv)
        self.Label.move(5, 160)
        self.NH_ICMP_NeighborAdv_Options = QtGui.QPushButton("Neighbor Discovery Options",self.NH_ICMP_NeighborAdv)
        self.NH_ICMP_NeighborAdv_Options.move(10, 180)
        self.connect(self.NH_ICMP_NeighborAdv_Options, QtCore.SIGNAL('clicked()'), self.slotNDOptHdr)
        
                    # Redirect
        
        self.NH_ICMP_Redirect = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_Redirect.setVisible(False)
        self.Label = QtGui.QLabel("Target Address:", self.NH_ICMP_Redirect)
        self.Label.move(5, 10)
        self.Label_2 = QtGui.QLabel("Destination Address:", self.NH_ICMP_Redirect)
        self.Label_2.move(5, 80)
        self.NH_ICMP_Redirect_tgtAddr = QtGui.QComboBox(self.NH_ICMP_Redirect)
        self.NH_ICMP_Redirect_tgtAddr.setGeometry(QtCore.QRect(10, 35, 300, 31))
        self.NH_ICMP_Redirect_tgtAddr.setEditable(True)
        self.NH_ICMP_Redirect_tgtAddr.setDuplicatesEnabled(True)
        self.NH_ICMP_Redirect_tgtAddr.addItem('::')
        self.NH_ICMP_Redirect_tgtAddr.addItem('ff01::1')
        self.NH_ICMP_Redirect_tgtAddr.addItem('ff02::1')
        self.NH_ICMP_Redirect_tgtAddr.addItem('ff80::1')
        self.NH_ICMP_Redirect_DstAddr = QtGui.QComboBox(self.NH_ICMP_Redirect)
        self.NH_ICMP_Redirect_DstAddr.setGeometry(QtCore.QRect(10, 105, 300, 31))
        self.NH_ICMP_Redirect_DstAddr.setEditable(True)
        self.NH_ICMP_Redirect_DstAddr.setDuplicatesEnabled(True)
        self.NH_ICMP_Redirect_DstAddr.addItem('::')
        self.NH_ICMP_Redirect_DstAddr.addItem('ff01::1')
        self.NH_ICMP_Redirect_DstAddr.addItem('ff02::1')
        self.NH_ICMP_Redirect_DstAddr.addItem('ff80::1')

        self.line = QtGui.QFrame(self.NH_ICMP_Redirect)
        self.line.setGeometry(QtCore.QRect(5, 150, width - 15, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label = QtGui.QLabel("Option(optional):", self.NH_ICMP_Redirect)
        self.Label.move(5, 160)
        self.NH_ICMP_Redirect_Options = QtGui.QPushButton("Neighbor Discovery Options",self.NH_ICMP_Redirect)
        self.NH_ICMP_Redirect_Options.move(10, 180)
        self.connect(self.NH_ICMP_Redirect_Options, QtCore.SIGNAL('clicked()'), self.slotNDOptHdr)

                    # Inverse Neighbor Discovery Solicitation

        self.NH_ICMP_InvNDSol = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_InvNDSol.setVisible(False)
        self.NH_ICMP_InvNDSol.setGeometry(QtCore.QRect(0, 0, width, height - 120))

        self.line = QtGui.QFrame(self.NH_ICMP_InvNDSol)
        self.line.setGeometry(QtCore.QRect(5, 150, width - 15, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label = QtGui.QLabel("Option(optional):", self.NH_ICMP_InvNDSol)
        self.Label.move(5, 160)
        self.NH_ICMP_InvNDSol_Options = QtGui.QPushButton("Neighbor Discovery Options",self.NH_ICMP_InvNDSol)
        self.NH_ICMP_InvNDSol_Options.move(10, 180)
        self.connect(self.NH_ICMP_InvNDSol_Options, QtCore.SIGNAL('clicked()'), self.slotNDOptHdr)

                    # Inverse Neighbor Discovery Advertisment

        self.NH_ICMP_InvNDAdv = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_InvNDAdv.setVisible(False)
        self.NH_ICMP_InvNDAdv.setGeometry(QtCore.QRect(0, 0, width, height - 120))

        self.line = QtGui.QFrame(self.NH_ICMP_InvNDAdv)
        self.line.setGeometry(QtCore.QRect(5, 150, width - 15, 2))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)

        self.Label = QtGui.QLabel("Option(optional):", self.NH_ICMP_InvNDAdv)
        self.Label.move(5, 160)
        self.NH_ICMP_InvNDAdv_Options = QtGui.QPushButton("Neighbor Discovery Options",self.NH_ICMP_InvNDAdv)
        self.NH_ICMP_InvNDAdv_Options.move(10, 180)
        self.connect(self.NH_ICMP_InvNDAdv_Options, QtCore.SIGNAL('clicked()'), self.slotNDOptHdr)
        
                    # other ICMP Type
        
        self.NH_ICMP_otherType = QtGui.QWidget(self.tab_NH_ICMP)
        self.NH_ICMP_otherType.setVisible(False)
        self.Label = QtGui.QLabel("Type:", self.NH_ICMP_otherType)
        self.Label.move(80, 40)
        self.NH_ICMP_otherType_Type = QtGui.QLineEdit("1", self.NH_ICMP_otherType)
        self.NH_ICMP_otherType_Type.setInputMask('000')
        self.NH_ICMP_otherType_Type.setGeometry(QtCore.QRect(120, 36, 60, 25))
        self.Label_2 = QtGui.QLabel("Code:", self.NH_ICMP_otherType)
        self.Label_2.move(77, 70)
        self.NH_ICMP_otherType_Code = QtGui.QLineEdit("0", self.NH_ICMP_otherType)
        self.NH_ICMP_otherType_Code.setInputMask('000')
        self.NH_ICMP_otherType_Code.setGeometry(QtCore.QRect(120, 66, 60, 25))
        self.Label_3 = QtGui.QLabel("Message:", self.NH_ICMP_otherType)
        self.Label_3.move(52, 100)
        self.NH_ICMP_otherType_Message = QtGui.QTextEdit("", self.NH_ICMP_otherType)
        self.NH_ICMP_otherType_Message.setGeometry(QtCore.QRect(120, 96, 200, 50))
        self.connect(self.NH_ICMP_otherType_Type, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)
        self.connect(self.NH_ICMP_otherType_Code, QtCore.SIGNAL('textChanged(QString)'), self.slotMax2_8)

                # TCP
        self.NH_TCP = QtGui.QWidget(self.tab_NextHeader)
        self.NH_TCP.setGeometry(QtCore.QRect(0, 60, width, 250))
        self.NH_TCP.setVisible(False)
        self.NH_TCP_Label = QtGui.QLabel("Source Port:", self.NH_TCP)
        self.NH_TCP_Label.move(width/2 - 270, 30)
        self.NH_TCP_SrcPort = QtGui.QLineEdit("20", self.NH_TCP)
        self.NH_TCP_SrcPort.setGeometry(QtCore.QRect(width/2 - 150, 26, 60, 25))
        self.NH_TCP_Label_2 = QtGui.QLabel("Destination Port:", self.NH_TCP)
        self.NH_TCP_Label_2.move(width/2 - 270, 70)
        self.NH_TCP_DstPort = QtGui.QLineEdit("80", self.NH_TCP)
        self.NH_TCP_DstPort.setGeometry(QtCore.QRect(width/2 - 150, 66, 60, 25))
        self.NH_TCP_Label_3 = QtGui.QLabel("Flags:", self.NH_TCP)
        self.NH_TCP_Label_3.move(width/2 - 270, 120)
        self.NH_TCP_Flag_URG = QtGui.QRadioButton("URG", self.NH_TCP)
        self.NH_TCP_Flag_URG.setAutoExclusive(False)
        self.NH_TCP_Flag_URG.move(width/2 - 250, 140)
        self.NH_TCP_Flag_ACK = QtGui.QRadioButton("ACK", self.NH_TCP)
        self.NH_TCP_Flag_ACK.setAutoExclusive(False)
        self.NH_TCP_Flag_ACK.move(width/2 - 250, 160)
        self.NH_TCP_Flag_PSH = QtGui.QRadioButton("PSH", self.NH_TCP)
        self.NH_TCP_Flag_PSH.setAutoExclusive(False)
        self.NH_TCP_Flag_PSH.move(width/2 - 190, 140)
        self.NH_TCP_Flag_RST = QtGui.QRadioButton("RST", self.NH_TCP)
        self.NH_TCP_Flag_RST.setAutoExclusive(False)
        self.NH_TCP_Flag_RST.move(width/2 - 190, 160)
        self.NH_TCP_Flag_SYN = QtGui.QRadioButton("SYN", self.NH_TCP)
        self.NH_TCP_Flag_SYN.setAutoExclusive(False)
        self.NH_TCP_Flag_SYN.move(width/2 - 130, 140)
        self.NH_TCP_Flag_SYN.setChecked(True)
        self.NH_TCP_Flag_FIN = QtGui.QRadioButton("FIN", self.NH_TCP)
        self.NH_TCP_Flag_FIN.setAutoExclusive(False)
        self.NH_TCP_Flag_FIN.move(width/2 - 130, 160)

                    # TCP Payload
        self.NH_TCP_Payload = QtGui.QWidget(self.NH_TCP) 
        self.NH_TCP_Payload.setGeometry(QtCore.QRect(width/2, 0, 300, 200))
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
        self.NH_UDP.setGeometry(QtCore.QRect(0, 60, width, 250))
        self.NH_UDP.setVisible(False)
        self.NH_UDP_Label = QtGui.QLabel("Source Port:", self.NH_UDP)
        self.NH_UDP_Label.move(width/2 - 270, 30)
        self.NH_UDP_SrcPort = QtGui.QLineEdit("53", self.NH_UDP)
        self.NH_UDP_SrcPort.setGeometry(QtCore.QRect(width/2 - 150, 26, 60, 25))
        self.NH_UDP_Label_2 = QtGui.QLabel("Destination Port:", self.NH_UDP)
        self.NH_UDP_Label_2.move(width/2 - 270, 70)
        self.NH_UDP_DstPort = QtGui.QLineEdit("53", self.NH_UDP)
        self.NH_UDP_DstPort.setGeometry(QtCore.QRect(width/2 - 150, 66, 60, 25))
                    # UDP Payload
        self.NH_UDP_Payload = QtGui.QWidget(self.NH_UDP)
        self.NH_UDP_Payload.setGeometry(QtCore.QRect(width/2 , 0, 300, 200))
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
        self.NH_NoNextHdr.setGeometry(QtCore.QRect(0, 60, width, 250))
        self.NH_NoNextHdr.setVisible(False)
        self.connect(self.NextHeader_Type, QtCore.SIGNAL('activated(int)'), self.NHConf)


        # Send Button
        self.SendButton = QtGui.QPushButton("Send", self)
        self.SendButton.move(width/2 - 110, height - 35)
        self.connect(self.SendButton, QtCore.SIGNAL('clicked(bool)'), self.slotSend)        

        # Clipboard Button
        self.ClipboardButton = QtGui.QPushButton("Clipboard", self)
        self.ClipboardButton.move(width/2 + 10, height - 35)
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
                self.NH_ICMP_NeighborAdv_tgtAddr.addItem(str(ipv6[d][2]))
                self.NH_ICMP_NeighborSol_tgtAddr.addItem(str(ipv6[d][2]))
                self.IPv6_DstAddr.addItem(str(ipv6[d][2]))
                self.NH_ICMP_Redirect_tgtAddr.addItem(str(ipv6[d][2]))
                self.NH_ICMP_Redirect_DstAddr.addItem(str(ipv6[d][2]))
                self.IPv6DstList.append(str(ipv6[d][2]))
            if ipv6[d][1] != (0 or 128) and self.IPv6DstList.contains(str(ipv6[d][0])+'1') == False:
                self.NH_ICMP_NeighborAdv_tgtAddr.addItem(str(ipv6[d][0])+'1')
                self.NH_ICMP_NeighborSol_tgtAddr.addItem(str(ipv6[d][0])+'1')
                self.IPv6_DstAddr.addItem(str(ipv6[d][0])+'1')
                self.NH_ICMP_Redirect_tgtAddr.addItem(str(ipv6[d][0])+'1')
                self.NH_ICMP_Redirect_DstAddr.addItem(str(ipv6[d][0])+'1')
                self.IPv6DstList.append(str(ipv6[d][0])+'1')

    def slotMax2_32(self):
        """This function sets the maximum Value of a Line Edit Widget to 4294967295 (2^32-1).
"""
        if self.NH_ICMP_PTB_MTU.text() != '' and int(self.NH_ICMP_PTB_MTU.text()) >= 4294967296:  
            self.NH_ICMP_PTB_MTU.setText('4294967295')
        if self.NH_ICMP_ParamProblem_Pointer.text() != '' and int(self.NH_ICMP_ParamProblem_Pointer.text()) >= 4294967296: 
            self.NH_ICMP_ParamProblem_Pointer.setText('4294967295')

    def slotMax2_20(self):
        """This function sets the maximum Value of a Line Edit Widget to 1048575 (2^20 - 1).
"""
        if self.IPv6_FlowLabel.text() != '' and int(self.IPv6_FlowLabel.text()) >= 1048576:
            self.IPv6_FlowLabel.setText('1048575')

    def slotMax2_16(self):
        """This function sets the maximum Value of a Line Edit Widget to 65535 (2^16 - 1).
"""
        if self.NH_ICMP_RouterAdv_RLTime.text() != '' and int(self.NH_ICMP_RouterAdv_RLTime.text()) >= 65536:
            self.NH_ICMP_RouterAdv_RLTime.setText('65535')
        if self.NH_ICMP_MultiQuery_MRD.text() != '' and int(self.NH_ICMP_MultiQuery_MRD.text()) >= 65536:
            self.NH_ICMP_MultiQuery_MRD.setText('65535')

    def slotMax2_8(self):
        """This function sets the maximum Value of a Line Edit Widget to 255 (2^8-1).
"""
        if self.NH_ICMP_otherType_Type.text() != '' and int(self.NH_ICMP_otherType_Type.text()) >= 256:
            self.NH_ICMP_otherType_Type.setText('255')
        if self.NH_ICMP_otherType_Code.text() != '' and int(self.NH_ICMP_otherType_Code.text()) >= 256:
            self.NH_ICMP_otherType_Code.setText('255')
        if self.NH_ICMP_RouterAdv_CHLim.text() != '' and int(self.NH_ICMP_RouterAdv_CHLim.text()) >= 256:
            self.NH_ICMP_RouterAdv_CHLim.setText('255')
        if self.NH_ICMP_DestUnreach_Code.text() != '' and int(self.NH_ICMP_DestUnreach_Code.text()) >= 256:
            self.NH_ICMP_DestUnreach_Code.setText('255')
        if self.NH_ICMP_PTB_Code.text() != '' and int(self.NH_ICMP_PTB_Code.text()) >= 256:
            self.NH_ICMP_PTB_Code.setText('255')
        if self.NH_ICMP_TimeExceeded_Code.text() != '' and int(self.NH_ICMP_TimeExceeded_Code.text()) >= 256:
            self.NH_ICMP_TimeExceeded_Code.setText('255')
        if self.NH_ICMP_ParamProblem_Code.text() != '' and int(self.NH_ICMP_ParamProblem_Code.text()) >= 256:
            self.NH_ICMP_ParamProblem_Code.setText('255')
        if self.IPv6_HopLimit.text() != '' and int(self.IPv6_HopLimit.text()) >= 256:
            self.IPv6_HopLimit.setText('255')
        if self.IPv6_TrafficClass.text() != '' and int(self.IPv6_TrafficClass.text()) >= 256:
            self.IPv6_TrafficClass.setText('255')

    def slotExpertMode(self):
        """The expert mode function activate more options in the IPv6 header.
"""
        self.IPv6_ExpertMode.setVisible(self.IPv6_Button_ExpertMode.isChecked())

    def NHConf(self):
        self.tab_NH_ICMP.setVisible(False)
        self.NH_TCP.setVisible(False)
        self.NH_UDP.setVisible(False)
        self.NH_NoNextHdr.setVisible(False)
        self.ICMP_Type.setVisible(False)
        if self.NextHeader_Type.currentText() == 'ICMP':
            self.tab_NH_ICMP.setVisible(True)
            self.ICMP_Type.setVisible(True)
        elif self.NextHeader_Type.currentText() == 'TCP':
            self.NH_TCP.setVisible(True)
        elif self.NextHeader_Type.currentText() == 'UDP':
            self.NH_UDP.setVisible(True)
        elif self.NextHeader_Type.currentText() == 'No Next Header':
            self.NH_NoNextHdr.setVisible(True)

    def ICMPConf(self):
        self.NH_ICMP_DestUnreach.setVisible(False)
        self.NH_ICMP_PTB.setVisible(False)
        self.NH_ICMP_TimeExceeded.setVisible(False)
        self.NH_ICMP_ParamProblem.setVisible(False)
        self.NH_ICMP_Ping.setVisible(False)
        self.NH_ICMP_EchoReply.setVisible(False)
        self.NH_ICMP_MultiQuery.setVisible(False)
        self.NH_ICMP_MultiReport.setVisible(False)
        self.NH_ICMP_MultiDone.setVisible(False)
        self.NH_ICMP_RouterSol.setVisible(False)
        self.NH_ICMP_RouterAdv.setVisible(False)
        self.NH_ICMP_NeighborSol.setVisible(False)
        self.NH_ICMP_NeighborAdv.setVisible(False)
        self.NH_ICMP_Redirect.setVisible(False)
        self.NH_ICMP_otherType.setVisible(False)
        self.NH_ICMP_InvNDSol.setVisible(False)
        self.NH_ICMP_InvNDAdv.setVisible(False)
        self.tabWidget.setTabEnabled(4,False)
        if self.ICMP_Type.currentText() == '1 - Destination Unreachable': self.NH_ICMP_DestUnreach.setVisible(True)
        elif self.ICMP_Type.currentText() == '2 - Packet Too Big': self.NH_ICMP_PTB.setVisible(True)
        elif self.ICMP_Type.currentText() == '3 - Time Exceeded': self.NH_ICMP_TimeExceeded.setVisible(True)
        elif self.ICMP_Type.currentText() == '4 - Parameter Problem': self.NH_ICMP_ParamProblem.setVisible(True)
        elif self.ICMP_Type.currentText() == '128 - Echo Request': self.NH_ICMP_Ping.setVisible(True)
        elif self.ICMP_Type.currentText() == '129 - Echo Reply': self.NH_ICMP_EchoReply.setVisible(True)
        elif self.ICMP_Type.currentText() == '130 - Multicast Listener Query': self.NH_ICMP_MultiQuery.setVisible(True)
        elif self.ICMP_Type.currentText() == '131 - Multicast Listener Report': self.NH_ICMP_MultiReport.setVisible(True)
        elif self.ICMP_Type.currentText() == '132 - Multicast Listener Done': self.NH_ICMP_MultiDone.setVisible(True)
        elif self.ICMP_Type.currentText() == '133 - Router Solicitation': self.NH_ICMP_RouterSol.setVisible(True)
        elif self.ICMP_Type.currentText() == '134 - Router Advertisement': self.NH_ICMP_RouterAdv.setVisible(True)
        elif self.ICMP_Type.currentText() == '135 - Neighbor Solicitation': self.NH_ICMP_NeighborSol.setVisible(True)
        elif self.ICMP_Type.currentText() == '136 - Neighbor Advertisement': self.NH_ICMP_NeighborAdv.setVisible(True)
        elif self.ICMP_Type.currentText() == '137 - Redirect': self.NH_ICMP_Redirect.setVisible(True)
        elif self.ICMP_Type.currentText() == '141 - Inverse Neighbor Discovery Solicitation': self.NH_ICMP_InvNDSol.setVisible(True)
        elif self.ICMP_Type.currentText() == '142 - Inverse Neighbor Discovery Advertisement': self.NH_ICMP_InvNDAdv.setVisible(True)
        elif self.ICMP_Type.currentText() == 'other ICMP Type': self.NH_ICMP_otherType.setVisible(True)

    def makeActions(self):
        """This function is use to connect the menubar with actions.
"""
        self._savepcapAction = QtGui.QAction("Save as &pcap", None)
        self._savePDFAction = QtGui.QAction("Save as PDF", None)
        self._saveAction = QtGui.QAction("&Save", None)
        self._loadAction = QtGui.QAction("&Load", None)
        self._exitAction = QtGui.QAction("&Exit", None)
        self._getIPv6AddrAction = QtGui.QAction("&Get local IPv6 Addresses", None)
        self._RoundTripAction = QtGui.QAction("&Round-Trip Time", None)
        self.connect(self._savepcapAction, QtCore.SIGNAL('triggered()'), self.slotSavepcap)
        self.connect(self._savePDFAction, QtCore.SIGNAL('triggered()'), self.slotSavePDF)
        self.connect(self._saveAction, QtCore.SIGNAL('triggered()'), self.slotSave)
        self.connect(self._loadAction, QtCore.SIGNAL('triggered()'), self.slotLoad)
        self.connect(self._exitAction, QtCore.SIGNAL('triggered()'), self.slotClose)
        self.connect(self._getIPv6AddrAction, QtCore.SIGNAL('triggered()'), self.slotGetIPv6Addr)
        self.connect(self._RoundTripAction, QtCore.SIGNAL('triggered()'), self.slotRoundTrip)

    def makeMenu(self):
        """This function creates the menubar.
"""
        menuBar = self.menuBar()
        fileMenu = menuBar.addMenu("&File")
        fileMenu.addAction(self._savepcapAction)
        fileMenu.addAction(self._savePDFAction)
        fileMenu.addAction(self._saveAction)
        fileMenu.addAction(self._loadAction)
        fileMenu.addAction(self._exitAction)
        toolMenu = menuBar.addMenu("&Tool")
        toolMenu.addAction(self._getIPv6AddrAction)
        toolMenu.addAction(self._RoundTripAction)

    def slotAddExtHdr(self):
        """This function open the class EH, which allows to create an extension header.
"""
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
        """This function open the class EH, with previously defined values. 
Then you can change the whole extension header or only the values of your extension header.
"""
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
        """If this function is used, the marked extension header will be deleted.
"""
        Row = self.ExtHdr_tableWidget.currentRow()
        if Row >= 0:
            self.ExtHdr_tableWidget.removeRow(Row)
            del self.IPv6.ExtHdr[Row]
            self.ExtHdr_tableWidget.setCurrentCell(Row,0)

    def slotNDOptHdr(self):

        self.setEnabled(False)
        ndopt = program_help_gui.NDOptHdr(self.IPv6.NDOpt, self.IPv6.Payload)
        ndopt.exec_()
        self.setEnabled(True)

    def ask_for_filename(self):
        """It opens a Dialog window where you can choose the pcap path for ICMP-Typs 1, 2, 3 and 4.
"""
        self.fileDialog = QtGui.QFileDialog.getOpenFileName(self,"FileDialog")
        self.NH_ICMP_PTB_PacketFile.setText(self.fileDialog) 
        self.NH_ICMP_DestUnreach_PacketFile.setText(self.fileDialog) 
        self.NH_ICMP_TimeExceeded_PacketFile.setText(self.fileDialog) 
        self.NH_ICMP_ParamProblem_PacketFile.setText(self.fileDialog)

    def slotPayload(self):
        """This function opens the Payload class and allows the user to send a whole packet form a pacp-file as payload from another IPv6 packet.
"""
        self.setEnabled(False)
        payload = program_help_gui.Payload(self.IPv6.Payload)
        payload.exec_()
        if ((self.IPv6.Payload['Capture File'] == '' or None)):
            self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Capture File are requiered\nto create a valid package!")
            self.NH_TCP_Payload_XLength.setChecked(True)
            self.NH_UDP_Payload_XLength.setChecked(True)
        self.setEnabled(True)

    def slotGetIPv6Addr(self):
        """This is a tool to get IPv6 addresses from a lokal network via Multicast Echo Request and Multicast Listener Discovery(MLD).
"""
        addresses=[]
        request = Ether()/IPv6(dst='ff02::1')/ICMPv6EchoRequest()
        ans, unans = srp(request, multi = 1, timeout = 10)
        query = Ether()/IPv6(dst='ff02::1',hlim=1)/IPv6ExtHdrHopByHop(autopad=0,nh=58)/ICMPv6MLQuery()
        query[2].options='\x05\x02\x00\x00\x00\x00'
        sendp(query)
        ans2 = sniff(filter='ip6', timeout=10)
        if ans != None:
            for packet in ans:
                addresses.append(packet[1][IPv6].src)
        if ans2 != None:
            for packet in ans2:
                addresses.append(packet[IPv6].src)
        uniqueAddr = set(addresses)
        for address in uniqueAddr:
            if self.IPv6DstList.contains(address) == False:
                self.IPv6_DstAddr.addItem(str(address)) 
                self.NH_ICMP_NeighborAdv_tgtAddr.addItem(str(address))
                self.NH_ICMP_NeighborSol_tgtAddr.addItem(str(address))
                self.NH_ICMP_Redirect_tgtAddr.addItem(str(address))
                self.NH_ICMP_Redirect_DstAddr.addItem(str(address))
                self.IPv6DstList.append(str(address))

    def slotRoundTrip(self):
        """This function opens a tool to send one or more pings and give the Round-Trip Time in a message box back. 
"""
        self.setEnabled(False)
        RoundTrip = program_help_gui.RoundTrip(self.IPv6DstList)
        RoundTrip.exec_()
        self.setEnabled(True)

    def slotSavepcap(self):
        """Will be used to save an IPv6 packet in a pcap file.
"""
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "",("pcap(*.pcap)"))
        if filename != '':
            if filename.endsWith('.pcap') == False:
                filename=(filename+'.pcap')
            self.creatIPv6(1, filename)

    def slotSavePDF(self):
        """Will be used to save an IPv6 packet in a PDF file.
"""
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "",("pdf(*.pdf)"))
        if filename != '':
            if filename.endsWith('.pdf') == False:
                filename=(filename+'.pdf')
            self.creatIPv6(4, filename)

    def slotSave(self):
        """Save the configure data.
"""
        self.creatIPv6(3, "")
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "")
        db = shelve.open(str(filename))
        db['EthHdr'] = self.IPv6.EthHdr
        db['IPHdr'] = self.IPv6.IPHdr
        db['ExtHdr'] = self.IPv6.ExtHdr
        db['indize'] = self.IPv6.indize
        db['RAconf'] = self.IPv6.RAconf
        db['NSconf'] = self.IPv6.NSconf
        db['NAconf'] = self.IPv6.NAconf
        db['NDOpt'] = self.IPv6.NDOpt
        db['ICMP'] = self.IPv6.ICMP
        db['PTB'] = self.IPv6.PTB
        db['TCP_UDP'] = self.IPv6.TCP_UDP
        db['Payload'] = self.IPv6.Payload
        db.close()

    def slotLoad(self):
        """Is used to load an IPv6 file into the GUI.
"""
        filename = QtGui.QFileDialog.getOpenFileName(self,"Load File", "")
        db = shelve.open(str(filename))
        self.IPv6.EthHdr = db['EthHdr']
        self.IPv6.IPHdr = db['IPHdr']
        self.IPv6.ExtHdr = db['ExtHdr']
        self.IPv6.indize = db['indize']
        self.IPv6.RAconf = db['RAconf']
        self.IPv6.NSconf = db['NSconf']
        self.IPv6.NAconf = db['NAconf']
        self.IPv6.NDOpt = db['NDOpt']
        self.IPv6.ICMP = db['ICMP']
        self.IPv6.PTB = db['PTB']
        self.IPv6.TCP_UDP = db['TCP_UDP']
        self.IPv6.Payload = db['Payload']

        if self.IPv6.EthHdr['LLDstAddr'] == None: self.LLDstAddr.setText('ff:ff:ff:ff:ff:ff')
        else: self.LLDstAddr.setText(str(self.IPv6.EthHdr['LLDstAddr']))
        if self.IPv6.EthHdr['LLSrcAddr'] == None: self.LLSrcAddr.setEditText(':::::')
        else: self.LLSrcAddr.setEditText(str(self.IPv6.EthHdr['LLSrcAddr']))
        self.Interface.setEditText(str(self.IPv6.EthHdr['Interface']))
        self.IPv6_DstAddr.setEditText(str(self.IPv6.IPHdr['DstIPAddr']))
        if self.IPv6.IPHdr['SrcIPAddr'] == None: self.IPv6_SrcAddr.setEditText('')
        else: self.IPv6_SrcAddr.setEditText(str(self.IPv6.IPHdr['SrcIPAddr']))
        self.IPv6_HopLimit.setText(str(self.IPv6.IPHdr['HopLimit']))
        self.IPv6_TrafficClass.setText(str(self.IPv6.IPHdr['TrafficClass']))
        self.IPv6_FlowLabel.setText(str(self.IPv6.IPHdr['FlowLabel']))
        self.IPv6_Button_ExpertMode.setChecked(self.IPv6.IPHdr['ExpertMode'])
        self.IPv6_ExpertMode.setVisible(self.IPv6.IPHdr['ExpertMode'])
        for num in range(0, self.ExtHdr_tableWidget.rowCount()): self.ExtHdr_tableWidget.removeRow(0)
        for num in range(0, len(self.IPv6.ExtHdr)-1):
            self.ExtHdr_tableWidget.insertRow(num)
            t1 = QtGui.QTableWidgetItem(self.IPv6.ExtHdr[num][0])
            self.ExtHdr_tableWidget.setItem(num, 0, t1)
            item = self.ExtHdr_tableWidget.item(num, 0)
            item.setFlags(Qt.Qt.ItemIsSelectable | Qt.Qt.ItemIsEnabled )
            item.setTextAlignment(Qt.Qt.AlignHCenter | Qt.Qt.AlignVCenter)
        if self.IPv6.indize == 0:
            self.NextHeader_Type.setCurrentIndex(self.NextHeader_Type.findText('ICMP'))
            if self.IPv6.ICMP['indize'] == 1:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('1 - Destination Unreachable'))
                self.NH_ICMP_DestUnreach_Code.setText(self.IPv6.ICMP['Code'])
                self.NH_ICMP_DestUnreach_PacketFile.setText(self.IPv6.Payload['Capture File'])
                self.NH_ICMP_DestUnreach_PacketNo.setText(self.IPv6.Payload['Packet No.'])
            elif self.IPv6.ICMP['indize'] == 2:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('2 - Packet Too Big'))
                self.NH_ICMP_PTB_Code.setText(self.IPv6.ICMP['Code'])
                self.NH_ICMP_PTB_MTU.setText(self.IPv6.PTB['MTU'])
                self.NH_ICMP_PTB_PacketFile.setText(self.IPv6.Payload['Capture File'])
                self.NH_ICMP_PTB_PacketNo.setText(self.IPv6.Payload['Packet No.'])
            elif self.IPv6.ICMP['indize'] == 3:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('3 - Time Exceeded'))
                self.NH_ICMP_TimeExceeded_Code.setText(self.IPv6.ICMP['Code'])
                self.NH_ICMP_TimeExceeded_PacketFile.setText(self.IPv6.Payload['Capture File'])
                self.NH_ICMP_TimeExceeded_PacketNo.setText(self.IPv6.Payload['Packet No.'])
            elif self.IPv6.ICMP['indize'] == 4:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('4 - Parameter Problem'))
                self.NH_ICMP_ParamProblem_Code.setText(self.IPv6.ICMP['Code'])
                self.NH_ICMP_ParamProblem_Pointer.setText(self.IPv6.ICMP['Pointer'])
                self.NH_ICMP_ParamProblem_PacketFile.setText(self.IPv6.Payload['Capture File'])
                self.NH_ICMP_ParamProblem_PacketNo.setText(self.IPv6.Payload['Packet No.'])
            elif self.IPv6.ICMP['indize'] == 128:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('128 - Echo Request'))
                self.NH_ICMP_Ping_Message.setPlainText(self.IPv6.ICMP['Message'])
            elif self.IPv6.ICMP['indize'] == 129:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('129 - Echo Reply'))
                self.NH_ICMP_EchoReply_Message.setPlainText(self.IPv6.ICMP['Message'])
            elif self.IPv6.ICMP['indize'] == 130:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('130 - Multicast Listener Query'))
                self.NH_ICMP_MultiQuery_MRD.setText(self.IPv6.ICMP['MRD'])
                self.NH_ICMP_MultiQuery_MLAddr.setEditText(str(self.IPv6.ICMP['MLAddr']))
            elif self.IPv6.ICMP['indize'] == 131:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('131 - Multicast Listener Report'))
                self.NH_ICMP_MultiReport_MLAddr.setEditText(str(self.IPv6.ICMP['MLAddr']))
            elif self.IPv6.ICMP['indize'] == 132:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('132 - Multicast Listener Done'))
                self.NH_ICMP_MultiDone_MLAddr.setEditText(str(self.IPv6.ICMP['MLAddr']))
            elif self.IPv6.ICMP['indize'] == 133:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('133 - Router Solicitation'))
            elif self.IPv6.ICMP['indize'] == 134:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('134 - Router Advertisement'))
                self.NH_ICMP_RouterAdv_CHLim.setText(self.IPv6.RAconf['CHLim'])
                self.NH_ICMP_RouterAdv_RLTime.setText(self.IPv6.RAconf['RLTime'])
                self.NH_ICMP_RouterAdv_MFlag.setChecked(self.IPv6.RAconf['M'])
                self.NH_ICMP_RouterAdv_OFlag.setChecked(self.IPv6.RAconf['O'])
            elif self.IPv6.ICMP['indize'] == 135:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('135 - Neighbor Solicitation'))
                self.NH_ICMP_NeighborSol_tgtAddr.setEditText( self.IPv6.NSconf['NS_tgtAddr'])
            elif self.IPv6.ICMP['indize'] == 136:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('136 - Neighbor Advertisement'))
                self.NH_ICMP_NeighborAdv_tgtAddr.setEditText(self.IPv6.NAconf['NA_tgtAddr'])
                self.NH_ICMP_NeighborAdv_RFlag.setChecked(self.IPv6.NAconf['R'])
                self.NH_ICMP_NeighborAdv_SFlag.setChecked(self.IPv6.NAconf['S'])
                self.NH_ICMP_NeighborAdv_OFlag.setChecked(self.IPv6.NAconf['O'])  
            elif self.IPv6.ICMP['indize'] == 137:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('137 - Redirect'))
                self.NH_ICMP_Redirect_tgtAddr.setEditText(self.IPv6.Redirect['Re_tgtAddr'])
                self.NH_ICMP_Redirect_DstAddr.setEditText(self.IPv6.Redirect['Re_DstAddr'])
            elif self.IPv6.ICMP['indize'] == 256:
                self.ICMP_Type.setCurrentIndex(self.ICMP_Type.findText('other ICMP Type'))
                self.NH_ICMP_otherType_Type.setText(self.IPv6.ICMP['Type'])
                self.NH_ICMP_otherType_Code.setText(self.IPv6.ICMP['Code'])
                self.NH_ICMP_otherType_Message.setPlainText(self.IPv6.ICMP['Message'])
        elif self.IPv6.indize == 1:
            self.NextHeader_Type.setCurrentIndex(self.NextHeader_Type.findText('TCP'))
            self.NH_TCP_SrcPort.setText(self.IPv6.TCP_UDP['SrcPort'])
            self.NH_TCP_DstPort.setText(self.IPv6.TCP_UDP['DstPort'])
            Flags=self.IPv6.TCP_UDP['Flags']
            if Flags >= 32:
                Flags -= 32
                self.NH_TCP_Flag_URG.setChecked(True)
            else: self.NH_TCP_Flag_URG.setChecked(False)
            if Flags >= 16:
                Flags -= 16
                self.NH_TCP_Flag_ACK.setChecked(True)
            else: self.NH_TCP_Flag_ACK.setChecked(False)
            if Flags >= 8:
                Flags -= 8
                self.NH_TCP_Flag_PSH.setChecked(True)
            else: self.NH_TCP_Flag_PSH.setChecked(False)
            if Flags >= 4:
                Flags -= 4
                self.NH_TCP_Flag_RST.setChecked(True)
            else: self.NH_TCP_Flag_RST.setChecked(False)
            if Flags >= 2:
                Flags -= 2
                self.NH_TCP_Flag_SYN.setChecked(True)
            else: self.NH_TCP_Flag_SYN.setChecked(False)
            if Flags >= 1:
                Flags -= 1
                self.NH_TCP_Flag_FIN.setChecked(True)
            else: self.NH_TCP_Flag_FIN.setChecked(False)
            if self.IPv6.Payload['indizeP'] == 0:
                self.NH_TCP_Payload_XLength.setChecked(True)
                self.NH_TCP_Payload_Length.setText(self.IPv6.Payload['Payloadlen'])
            elif self.IPv6.Payload['indizeP'] == 1:
                self.NH_TCP_Payload_PayString.setChecked(True)
                self.NH_TCP_Payload_String.setText(self.IPv6.Payload['PayloadString'])
            elif self.IPv6.Payload['indizeP'] == 2: self.NH_TCP_Payload_PcapFile.setChecked(True)
            elif self.IPv6.Payload['indizeP'] == 3: self.NH_TCP_Payload_NoPayload.setChecked(True)
        elif self.IPv6.indize == 2:
            self.NextHeader_Type.setCurrentIndex(self.NextHeader_Type.findText('UDP'))
            self.NH_UDP_SrcPort.setText(self.IPv6.TCP_UDP['SrcPort'])
            self.NH_UDP_DstPort.setText(self.IPv6.TCP_UDP['DstPort'])
            if self.IPv6.Payload['indizeP'] == 0:
                self.NH_UDP_Payload_XLength.setChecked(True)
                self.NH_UDP_Payload_Length.setText(self.IPv6.Payload['Payloadlen'])
            elif self.IPv6.Payload['indizeP'] == 1:
                self.NH_UDP_Payload_PayString.setChecked(True)
                self.NH_UDP_Payload_String.setText(self.IPv6.Payload['PayloadString'])
            elif self.IPv6.Payload['indizeP'] == 2: self.NH_UDP_Payload_PcapFile.setChecked(True)
            elif self.IPv6.Payload['indizeP'] == 3: self.NH_UDP_Payload_NoPayload.setChecked(True)
        elif self.IPv6.indize == 3:
            self.NextHeader_Type.setCurrentIndex(self.NextHeader_Type.findText('No Next Header'))
        self.NHConf()
        self.ICMPConf()
        

    def slotSend(self):
        """This function starts the process of sending a packet.
"""
        self.creatIPv6(0, '')

    def slotClipboard(self):
        """This function starts the process of save a packet to clipboard.
"""
        self.creatIPv6(2, '')

    def slotClose(self):
        """This function close the main window of the GUI.
"""
        ret = QtGui.QMessageBox.question(None, "Quit?", "You want to close this program?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if ret == QtGui.QMessageBox.Yes:
            self.close()

    def creatIPv6(self, Option, File):
        """This function builds a IPv6 packet and open the :class:`Buildit` class.

:param Option: option for further processing
:type Option: int 
:param File: path to save into a pcap-file
:type File: file

options::

    0 -- send
    1 -- save as *.pcap 
    2 -- save to clipboard
    3 -- save in a Data Base
    4 -- save as PDF
        """
        self.IPv6.EthHdr['LLDstAddr'] = str(self.LLDstAddr.text())
        self.IPv6.EthHdr['LLSrcAddr'] = str(self.LLSrcAddr.currentText())
        self.IPv6.EthHdr['Interface'] = str(self.Interface.currentText())
        self.IPv6.IPHdr['DstIPAddr'] = str(self.IPv6_DstAddr.currentText())
        self.IPv6.IPHdr['SrcIPAddr'] = str(self.IPv6_SrcAddr.currentText())
        self.IPv6.IPHdr['HopLimit'] = int(self.IPv6_HopLimit.text())
        self.IPv6.IPHdr['TrafficClass'] = int(self.IPv6_TrafficClass.text())
        self.IPv6.IPHdr['FlowLabel'] = int(self.IPv6_FlowLabel.text())
        self.IPv6.IPHdr['ExpertMode'] = self.IPv6_Button_ExpertMode.isChecked()
        if self.NextHeader_Type.currentText() == 'ICMP':
            self.IPv6.indize = 0
            if self.ICMP_Type.currentText() == '1 - Destination Unreachable':
                self.IPv6.ICMP['indize'] = 1
                if self.NH_ICMP_DestUnreach_Code.text() == '': self.NH_ICMP_DestUnreach_Code.setText(self.IPv6.ICMP['Code'])
                self.IPv6.ICMP['Code'] = self.NH_ICMP_DestUnreach_Code.text()
                self.IPv6.Payload['Capture File'] = self.NH_ICMP_DestUnreach_PacketFile.text()
                self.IPv6.Payload['Packet No.'] = self.NH_ICMP_DestUnreach_PacketNo.text()
                if self.IPv6.Payload['Capture File'] == '' or self.IPv6.Payload['Packet No.'] == '':
                    self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Pcap-File and Packet No. are requiered\nto create a valid package!")
                    return
            if self.ICMP_Type.currentText() == '2 - Packet Too Big':
                self.IPv6.ICMP['indize'] = 2
                if self.NH_ICMP_PTB_Code.text() == '': self.NH_ICMP_PTB_Code.setText(self.IPv6.ICMP['Code'])
                if self.NH_ICMP_PTB_MTU.text() == '': self.NH_ICMP_PTB_MTU.setText(self.IPv6.PTB['MTU'])
                self.IPv6.ICMP['Code'] = self.NH_ICMP_PTB_Code.text()
                self.IPv6.PTB['MTU'] = self.NH_ICMP_PTB_MTU.text()
                self.IPv6.Payload['Capture File'] = self.NH_ICMP_PTB_PacketFile.text()
                self.IPv6.Payload['Packet No.'] = self.NH_ICMP_PTB_PacketNo.text()
                if self.IPv6.Payload['Capture File'] == '' or self.IPv6.Payload['Packet No.'] == '':
                    self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Pcap-File and Packet No. are requiered\nto create a valid package!")
                    return
            if self.ICMP_Type.currentText() == '3 - Time Exceeded':
                self.IPv6.ICMP['indize'] = 3
                if self.NH_ICMP_TimeExceeded_Code.text() == '': self.NH_ICMP_TimeExceeded_Code.setText(self.IPv6.ICMP['Code'])
                self.IPv6.ICMP['Code'] = self.NH_ICMP_TimeExceeded_Code.text()
                self.IPv6.Payload['Capture File'] = self.NH_ICMP_TimeExceeded_PacketFile.text()
                self.IPv6.Payload['Packet No.'] = self.NH_ICMP_TimeExceeded_PacketNo.text()
                if self.IPv6.Payload['Capture File'] == '' or self.IPv6.Payload['Packet No.'] == '':
                    self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Pcap-File and Packet No. are requiered\nto create a valid package!")
                    return
            if self.ICMP_Type.currentText() == '4 - Parameter Problem':
                self.IPv6.ICMP['indize'] = 4
                if self.NH_ICMP_ParamProblem_Code.text() == '': self.NH_ICMP_ParamProblem_Code.setText(self.IPv6.ICMP['Code'])
                if self.NH_ICMP_ParamProblem_Pointer.text() == '': self.NH_ICMP_ParamProblem_Pointer.setText(elf.IPv6.ICMP['Pointer'])
                self.IPv6.ICMP['Code'] = self.NH_ICMP_ParamProblem_Code.text()
                self.IPv6.ICMP['Pointer'] = self.NH_ICMP_ParamProblem_Pointer.text()
                self.IPv6.Payload['Capture File'] = self.NH_ICMP_ParamProblem_PacketFile.text()
                self.IPv6.Payload['Packet No.'] = self.NH_ICMP_ParamProblem_PacketNo.text()
                if self.IPv6.Payload['Capture File'] == '' or self.IPv6.Payload['Packet No.'] == '':
                    self.err_msg = QtGui.QMessageBox.information(None, "Info!", "Pcap-File and Packet No. are requiered\nto create a valid package!")
                    return
            elif self.ICMP_Type.currentText() == '128 - Echo Request':
                self.IPv6.ICMP['indize'] = 128
                self.IPv6.ICMP['Message'] = str(self.NH_ICMP_Ping_Message.toPlainText())
            elif self.ICMP_Type.currentText() == '129 - Echo Reply':
                self.IPv6.ICMP['indize'] = 129
                self.IPv6.ICMP['Message'] = str(self.NH_ICMP_EchoReply_Message.toPlainText())
            elif self.ICMP_Type.currentText() == '130 - Multicast Listener Query':         
                self.IPv6.ICMP['indize'] = 130
                if self.NH_ICMP_MultiQuery_MRD.text() == '': self.NH_ICMP_MultiQuery_MRD.setText(self.IPv6.ICMP['MRD'])
                self.IPv6.ICMP['MRD'] = self.NH_ICMP_MultiQuery_MRD.text()
                self.IPv6.ICMP['MLAddr'] = str(self.NH_ICMP_MultiQuery_MLAddr.currentText())
            elif self.ICMP_Type.currentText() == '131 - Multicast Listener Report':
                self.IPv6.ICMP['indize'] = 131
                self.IPv6.ICMP['MLAddr'] = str(self.NH_ICMP_MultiReport_MLAddr.currentText())
            elif self.ICMP_Type.currentText() == '132 - Multicast Listener Done':
                self.IPv6.ICMP['indize'] = 132
                self.IPv6.ICMP['MLAddr'] = str(self.NH_ICMP_MultiDone_MLAddr.currentText())
            elif self.ICMP_Type.currentText() == '133 - Router Solicitation':
                self.IPv6.ICMP['indize'] = 133
            elif self.ICMP_Type.currentText() == '134 - Router Advertisement':
                self.IPv6.ICMP['indize'] = 134
                self.IPv6.RAconf['CHLim'] = self.NH_ICMP_RouterAdv_CHLim.text()
                if self.IPv6.RAconf['CHLim'] == '': self.IPv6.RAconf['CHLim'] = '0'
                self.IPv6.RAconf['RLTime'] = self.NH_ICMP_RouterAdv_RLTime.text()
                if self.IPv6.RAconf['RLTime'] == '': self.IPv6.RAconf['RLTime'] = '1800'
                self.IPv6.RAconf['M'] = self.NH_ICMP_RouterAdv_MFlag.isChecked()
                self.IPv6.RAconf['O'] = self.NH_ICMP_RouterAdv_OFlag.isChecked()  
            elif self.ICMP_Type.currentText() == '135 - Neighbor Solicitation':
                self.IPv6.ICMP['indize'] = 135
                self.IPv6.NSconf['NS_tgtAddr'] = self.NH_ICMP_NeighborSol_tgtAddr.currentText()
                if self.IPv6.NSconf['NS_tgtAddr'] == '': self.IPv6.NSconf['NS_tgtAddr'] = '::'
            elif self.ICMP_Type.currentText() == '136 - Neighbor Advertisement':
                self.IPv6.ICMP['indize'] = 136
                self.IPv6.NAconf['NA_tgtAddr'] = self.NH_ICMP_NeighborAdv_tgtAddr.currentText()
                if self.IPv6.NAconf['NA_tgtAddr'] == '': self.IPv6.NAconf['NA_tgtAddr'] = ':::::'
                self.IPv6.NAconf['R'] = self.NH_ICMP_NeighborAdv_RFlag.isChecked()
                self.IPv6.NAconf['S'] = self.NH_ICMP_NeighborAdv_SFlag.isChecked()
                self.IPv6.NAconf['O'] = self.NH_ICMP_NeighborAdv_OFlag.isChecked()
            elif self.ICMP_Type.currentText() == '137 - Redirect':
                self.IPv6.ICMP['indize'] = 137
                if self.NH_ICMP_Redirect_tgtAddr.currentText() == '': self.NH_ICMP_Redirect_tgtAddr.setEditText('::')
                if self.NH_ICMP_Redirect_DstAddr.currentText() == '': self.NH_ICMP_Redirect_DstAddr.setEditText('::')
                self.IPv6.Redirect['Re_tgtAddr'] = str(self.NH_ICMP_Redirect_tgtAddr.currentText())
                self.IPv6.Redirect['Re_DstAddr'] = str(self.NH_ICMP_Redirect_DstAddr.currentText())
            elif self.ICMP_Type.currentText() == 'other ICMP Type':
                self.IPv6.ICMP['indize'] = 256
                if self.NH_ICMP_otherType_Type.text() == '': self.NH_ICMP_otherType_Type.setText(self.IPv6.ICMP['Type'])
                if self.NH_ICMP_otherType_Code.text() == '': self.NH_ICMP_otherType_Code.setText(self.IPv6.ICMP['Code'])
                self.IPv6.ICMP['Type'] = self.NH_ICMP_otherType_Type.text()
                self.IPv6.ICMP['Code'] = self.NH_ICMP_otherType_Code.text()
                self.IPv6.ICMP['Message'] = str(self.NH_ICMP_otherType_Message.toPlainText())
            if self.IPv6.ICMP['MLAddr'] == '': self.IPv6.ICMP['MLAddr'] = '::'
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
            if self.NH_UDP_SrcPort.text() == '': self.NH_UDP_SrcPort.setText('53')
            if self.NH_UDP_DstPort.text() == '': self.NH_UDP_DstPort.setText('53')
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
        
        if Option == 3: return
        program_background.Buildit(Option, File, self.IPv6)



if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    m = Main()
    app.exec_()
