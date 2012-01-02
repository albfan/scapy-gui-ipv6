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
from struct import *

class IPv6Packet:
    """This class are needed to create an IPv6 array, which save informations for the packet generation.

    There are never all values needed.

    :returns: -- EthHdr -- Ethernet Header (link-layer source address, -destination address, Interface)

              -- IPHdr  -- IPv6 Header (source and destination IPv6 address)

              -- indize -- int value for the identification of the next header:: 

                        0 = ICMP
                        1 = TCP
                        2 = UDP
                        3 = no Next Header

              -- RAconf -- Router Advertisement (Prefix, Prefix Length, link-layer source address, M and O Flag, Router Life Time, Cur Hop Limit)

              -- NAconf -- Neighbor Advertisement (Target IPv6 address, Flags)

              -- NSconf -- Neighbor Solicitation (Target IPv6 address)

              -- NDOpt  -- Neighbor Discovery Options (Option, link-layer source and destination address , MTU, Prefix, Prefix Length, flags, Valid Lifetime, Preferred Lifetime, Source Address List, Target Address List)
                            -- Option -- 7 bit binary value for the identification of the Neighbor Discovery Options:: 

                                xxxxxx1 = Source Link-layer Address
                                xxxxx1x = Target Link-layer Address
                                xxxx1xx = Prefix Information
                                xxx1xxx = Redirected Header
                                xx1xxxx = MTU
                                x1xxxxx = Source Address List
                                1xxxxxx = Target Address List

              -- Redirect -- Redirect Message (Target IPv6 address, Destination IPv6 address)

              -- ICMP   -- Internet Control Message Protocol (Code, Type, Message, indize)
                            -- indize -- int value for the identification of the ICMP type:: 

                                  1 = Destination Unreachable
                                  2 = Packet Too Big
                                  3 = Time Exceeded
                                  4 = Parameter Problem
                                128 = Echo Request
                                129 = Echo Reply
                                130 = Multicast Listener Query
                                131 = Multicast Listener Report
                                132 = Multicast Listener Done
                                133 = Router Solicitation
                                134 = Router Advertisement
                                135 = Neighbor Solicitation
                                136 = Neighbor Advertisement
                                137 = Redirect
                                141 = Inverse Neighbor Discovery Solicitation
                                142 = Inverse Neighbor Discovery Advertisement
                                256 = other Type

              -- PTB    -- ICMP Packet too big (MTU)

              -- TCP_UDP -- Transmission Control and User Datagram Protocol (source and destination Port, TCP-Flags)

              -- Payload -- Payload Info (Payload Length, Payload String, Capture File, File no., indizeP )
                            -- indizeP -- int value for the identification of the payload option::

                                0 = String with 'X' * len
                                1 = String
                                2 = pcap File
                                3 = no Payload
    
    """
    EthHdr = {'LLSrcAddr': None, 'LLDstAddr': None, 'Interface': None}
    IPHdr = {'SrcIPAddr': None, 'DstIPAddr': None, 'HopLimit': 64, 'TrafficClass': 0, 'FlowLabel': 0 , 'ExpertMode': False}
    ExtHdr = [['','','','']]
    indize = 0
    RAconf = {'M': False, 'O': False, 'RLTime':'1800', 'CHLim': '255'}
    NSconf = {'NS_tgtAddr': '::'}
    NAconf = {'NA_tgtAddr': '::', 'R': True, 'S': False, 'O': True}
    NDOpt = {'Option': 0, 'ND_SrcLLAddr': '00:00:00:00:00:00', 'ND_DstLLAddr': 'FF:FF:FF:FF:FF:FF', 'MTU': 1280, 'Prefix': 'fd00:141:64:1::', 'Prefixlen':'64', 'L': True, 'A': True, 'ValidL': '4294967295', 'PreferredL': '4294967295', 'SrcAddrList': [], 'TgtAddrList': []}
    Redirect = {'Re_tgtAddr': '::', 'Re_DstAddr': '::'}
    ICMP = {'indize': 128, 'Type': '1', 'Code': '0', 'Message': '', 'Pointer': '6', 'MRD': 10000, 'MLAddr': '::'}
    PTB = {'MTU': '1280'}
    TCP_UDP = {'SrcPort': '20', 'DstPort': '80', 'Flags': 2}
    Payload = {'indizeP': 0, 'Payloadlen': '1', 'PayloadString': 'X', 'Capture File': '', 'Packet No.': '1'}
  


class Buildit:
    """This class creates the scapy IPv6 packet and handles with it according to the option.
    
    :param Option: option for further processing
    :type Option: int 
    :param File: path to save into a pcap-file
    :type File: file
    :param IPv6Packet: IPv6 Packet with packet information
    :type IPv6Packet: class.IPv6Packet

    options::

            0 -- send
            1 -- save as *.pcap 
            2 -- save to clipboard

    """
    
    def __init__(self,Option, File, IPv6Packet):

        self.IPv6 = IPv6Packet
        self.Options = []
        self.IPv6packet = {'EthHeader':None,'IPHeader':None,
                           'ExtHeader':None,'NextHeader':None}
        self.IPv6Scapy = None

        ##################
        ## Ethernet Header


        self.IPv6packet['EthHeader'] = Ether()

        if self.IPv6.EthHdr['LLDstAddr'] != 'ff:ff:ff:ff:ff:ff': 
            self.IPv6packet['EthHeader'].dst = self.IPv6.EthHdr['LLDstAddr']
        if self.IPv6.EthHdr['LLSrcAddr'] != ':::::':
            self.IPv6packet['EthHeader'].src = self.IPv6.EthHdr['LLSrcAddr']


        ##############
        ## IPv6 Header

        self.IPv6packet['IPHeader'] = IPv6()
        if self.IPv6.IPHdr['SrcIPAddr'] != ('' and None): 
            self.IPv6packet['IPHeader'].src=self.IPv6.IPHdr['SrcIPAddr']
        if self.IPv6.IPHdr['DstIPAddr'] != ('' and None): 
            self.IPv6packet['IPHeader'].dst=self.IPv6.IPHdr['DstIPAddr']
        if self.IPv6.IPHdr['ExpertMode'] == True:
            self.IPv6packet['IPHeader'].hlim = self.IPv6.IPHdr['HopLimit']
            self.IPv6packet['IPHeader'].tc = self.IPv6.IPHdr['TrafficClass']
            self.IPv6packet['IPHeader'].fl = self.IPv6.IPHdr['FlowLabel']

        ############################
        ## add extension header if set

        self.NumExtHdr = len(self.IPv6.ExtHdr)
        if self.NumExtHdr > 0:
            self.IPv6packet['ExtHeader'] = self.BuildExtHdr(self.NumExtHdr - 1)
        else:
            self.IPv6packet['ExtHeader'] = None

        ########################
        ## add next header

        self.IPv6packet['NextHeader'] = self.BuildNextHeader()

        ############
        ## get iface

        if self.IPv6.EthHdr['Interface'] != '':
            Interface = str(self.IPv6.EthHdr['Interface'])
        else:
            Interface = None

        ##########
        ## send or save (pcap or Clipbord)
		
        if self.IPv6packet['ExtHeader'] == (None or '') and self.IPv6packet['NextHeader'] != None:
            self.IPv6Scapy = (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['NextHeader'])
        elif self.IPv6packet['ExtHeader'] == (None or '') and self.IPv6packet['NextHeader'] == None:
            self.IPv6Scapy = (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader'])
        elif self.IPv6packet['ExtHeader'] != (None or '') and self.IPv6packet['NextHeader'] != None:
            self.IPv6Scapy = (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader']/self.IPv6packet['NextHeader'])
        elif self.IPv6packet['ExtHeader'] != (None or '') and self.IPv6packet['NextHeader'] == None:
            self.IPv6Scapy = (self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader'])

        if self.IPv6.indize == 0 and self.IPv6.ICMP['indize'] in (130, 131, 132): # Next Header for Multicast Listener Messages
            self.IPv6Scapy[len(self.IPv6.ExtHdr)].nh = 58

        Command = self.IPv6Scapy.command()

        if len(self.Options) >= 1:      # Options of the Extension Header Hop By Hop und Destination
            for d in self.Options:
                if d[1] == 'Pad1 Option':
                    self.IPv6Scapy[d[0]+2].autopad = 0
                    self.IPv6Scapy[d[0]+2].options = '\x00\x00\x00\x00\x00\x00'
                elif d[1] == 'other Option':
                    length1=len(self.IPv6Scapy[d[0]+3])
                    self.IPv6Scapy[d[0]+2].autopad = 0
                    self.IPv6Scapy[d[0]+2].options = ((pack('B',int(str(d[2]).split()[0]))) +
                                                      (pack('B',int(str(d[2]).split()[-1]))) + 
                                                      str(str(d[3]).decode('string_escape')))
                    length2=len(self.IPv6Scapy[d[0]+2])
                    while ((length2-length1) % 8) != 0:
                        self.IPv6Scapy[d[0]+2].options += '\x00'
                        length2=len(self.IPv6Scapy[d[0]+2])

        if Option == 0:
            ## send
            sendp(self.IPv6Scapy, iface = Interface)
                
        elif Option == 1:
            ## save as .pcap
            wrpcap(File, self.IPv6Scapy)
                
        elif Option == 2:
            ## save to Clipboard
            Clipboard = QtGui.QApplication.clipboard()
            Clipboard.setText(Command)
                
        elif Option == 4:
            ## save as .pdf
            self.IPv6Scapy.pdfdump(str(File), layer_shift=5)

        ## show sourcecode
        disp_sourcecode = QtGui.QMessageBox.information(None, "Scapy Quellcode", "Scapy Quellcode:\n\n%s" % Command )

    ###############
    ## Build Extension Header

    def  BuildExtHdr(self, Num):
        """creates a extension header in scapy code.
        
        :param Num: number of extension header
        :type Num: int

        """
        ExtensionHeader = ''
        for d in range(Num):
            if self.IPv6.ExtHdr[d][0] == 'Hop By Hop Options':
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrHopByHop()
                else:
                    ExtensionHeader = ExtensionHeader/ IPv6ExtHdrHopByHop()
                if self.IPv6.ExtHdr[d][1] != 'PadN Option':
                    self.Options.append([d,self.IPv6.ExtHdr[d][1],self.IPv6.ExtHdr[d][2],self.IPv6.ExtHdr[d][3]])
            elif self.IPv6.ExtHdr[d][0] == 'Destination Options':
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrDestOpt()
                else:
                    ExtensionHeader = ExtensionHeader/ IPv6ExtHdrDestOpt()
                if self.IPv6.ExtHdr[d][1] != 'PadN Option':
                    self.Options.append([d,self.IPv6.ExtHdr[d][1],self.IPv6.ExtHdr[d][2],self.IPv6.ExtHdr[d][3]])
            elif self.IPv6.ExtHdr[d][0] == 'Routing':
                i = len(self.IPv6.ExtHdr[d][1])
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrRouting(addresses = self.IPv6.ExtHdr[d][1])
                else:
                    ExtensionHeader = ExtensionHeader/ IPv6ExtHdrRouting(addresses = self.IPv6.ExtHdr[d][1])
            elif self.IPv6.ExtHdr[d][0] == 'Fragmentation':
                if self.IPv6.ExtHdr[d][3] == 0:
                    self.M_Flag = '0'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.IPv6.ExtHdr[d][3], offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/ IPv6ExtHdrFragment(m = 0, offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                else:
                    self.M_Flag = '1'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.IPv6.ExtHdr[d][3], offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/ IPv6ExtHdrFragment(m = 1, offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
        return(ExtensionHeader)

    ###############
    ## Build Next Header

    def BuildNextHeader(self):
        """This function check which next header is chosen (by looking to the ``IPv6.indize``) and if ``IPv6.indize == 0`` it choose the ICMP type (by looking to the ``IPv6.ICMP['indize']``).
        
        After the detection of the next header protocol, a corresponding function will open.

        ``IPv6.indize``::
            
             0 = ICMP
             1 = TCP
             2 = UDP
             3 = no Next Header

        ``IPv6.ICMP['indize']``::

               1 = Destination Unreachable
               2 = Packet Too Big
               3 = Time Exceeded
               4 = Parameter Problem
             128 = Echo Request
             129 = Echo Reply
             130 = Multicast Listener Query
             131 = Multicast Listener Report
             132 = Multicast Listener Done
             133 = Router Solicitation
             134 = Router Advertisement
             135 = Neighbor Solicitation
             136 = Neighbor Advertisement
             137 = Redirect
             141 = Inverse Neighbor Discovery Solicitation
             142 = Inverse Neighbor Discovery Advertisement
             256 = other Type
        """

        if self.IPv6.indize == 0:               # ICMP
            if self.IPv6.ICMP['indize'] == 1:          # Destination Unreachable
                NextHeader = self.BuildICMPv6_DestUnreach()
            elif self.IPv6.ICMP['indize'] == 2:        # Packet Too Big
                NextHeader = self.BuildICMPv6_PacketTooBig()
            elif self.IPv6.ICMP['indize'] == 3:        # Time Exceeded
                NextHeader = self.BuildICMPv6_TimeExceeded()
            elif self.IPv6.ICMP['indize'] == 4:        # Parameter Problem
                NextHeader = self.BuildICMPv6_ParamProblem()
            elif self.IPv6.ICMP['indize'] == 128:      # Ping
                NextHeader = self.BuildICMPv6_Ping()
            elif self.IPv6.ICMP['indize'] == 129:      # Echo Reply
                NextHeader = self.BuildICMPv6_EchoReply()
            elif self.IPv6.ICMP['indize'] == 130:      # Multicast Listener Query
                NextHeader = self.BuildICMPv6_MLQuery()
            elif self.IPv6.ICMP['indize'] == 131:      # Multicast Listener Report
                NextHeader = self.BuildICMPv6_MLReport()
            elif self.IPv6.ICMP['indize'] == 132:      # Multicast Listener Done
                NextHeader = self.BuildICMPv6_MLDone()
            elif self.IPv6.ICMP['indize'] == 133:      # Router Solicitation
                NextHeader = self.BuildICMPv6_RS()
            elif self.IPv6.ICMP['indize'] == 134:      # Router Advetisement
                NextHeader = self.BuildICMPv6_RA()
            elif self.IPv6.ICMP['indize'] == 135:      # Neighbor Solicitation
                NextHeader = self.BuildICMPv6_NS()
            elif self.IPv6.ICMP['indize'] == 136:      # Neighbor Advetisement
                NextHeader = self.BuildICMPv6_NA()
            elif self.IPv6.ICMP['indize'] == 137:      # Redirect
                NextHeader = self.BuildICMPv6_Redirect()
            elif self.IPv6.ICMP['indize'] == 141:      # Inverse Neighbor Discovery Solicitation
                NextHeader = self.BuildICMPv6_INDS()
            elif self.IPv6.ICMP['indize'] == 142:      # Inverse Neighbor Discovery Advetisement
                NextHeader = self.BuildICMPv6_INDA()
            elif self.IPv6.ICMP['indize'] == 256:      # ICMP Unknown
                NextHeader = self.BuildICMPv6_Unknown()
            if self.IPv6.ICMP['indize'] == 133 or 134 or 135 or 136 or 137 or 141 or 142:      # ND Option
                NextHeader = self.BuildICMPv6_NDOpt(NextHeader)
        elif self.IPv6.indize == 1:             # TCP
            NextHeader = self.BuildTCP()
        elif self.IPv6.indize == 2:             # UDP
            NextHeader = self.BuildUDP()
        elif self.IPv6.indize == 3:             # No Next Header
            NextHeader = self.BuildNoNextHeader()
        else:
            self.Fehler = QtGui.QMessageBox.information(None, '', 'Sorry this Next Header is not implemented yet.')

        return(NextHeader)

    ## Destination Unreachable

    def BuildICMPv6_DestUnreach(self):
        """This function creates a destination unreachable message for the scapy code.
"""
        DestUnreach = ICMPv6DestUnreach(code=int(self.IPv6.ICMP['Code']))

        if self.IPv6.Payload['Capture File'] != '':
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            if self.IPv6.Payload['Packet No.'] != '':
                no = int(self.IPv6.Payload['Packet No.'])-1
            else:
                no = 0
            DestUnreach = DestUnreach/capture[no][IPv6]
        return(DestUnreach)

    ## Packet Too Big

    def BuildICMPv6_PacketTooBig(self):
        """This function creates a packet too big message for the scapy code.

For the packet too big message is the mtu necessary. It is set to 1280 by default.
Optional you inlude a packet from a pcap file as payload.
"""
        if self.IPv6.PTB['MTU'] != '': 
            MTU = self.IPv6.PTB['MTU']
        else:
            MTU = None
        q = ICMPv6PacketTooBig(mtu=int(MTU), code=int(self.IPv6.ICMP['Code']))

        if self.IPv6.Payload['Capture File'] != '':
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            if self.IPv6.Payload['Packet No.'] != '':
                no = int(self.IPv6.Payload['Packet No.'])-1
            else:
                no = 0
            q = q/capture[no][IPv6]
        return(q)

    ## Time Exceeded

    def BuildICMPv6_TimeExceeded(self):
        """This function creates a destination unreachable message for the scapy code.
"""
        TimeEx = ICMPv6TimeExceeded(code=int(self.IPv6.ICMP['Code']))

        if self.IPv6.Payload['Capture File'] != '':
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            if self.IPv6.Payload['Packet No.'] != '':
                no = int(self.IPv6.Payload['Packet No.'])-1
            else:
                no = 0
            TimeEx = TimeEx/capture[no][IPv6]
        return(TimeEx)

    ## Parameter Problem

    def BuildICMPv6_ParamProblem(self):
        """This function creates a parameter problem message for the scapy code.
"""
        ParameterProb = ICMPv6ParamProblem(code=int(self.IPv6.ICMP['Code']), ptr=int(self.IPv6.ICMP['Pointer']))

        if self.IPv6.Payload['Capture File'] != '':
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            if self.IPv6.Payload['Packet No.'] != '':
                no = int(self.IPv6.Payload['Packet No.'])-1
            else:
                no = 0
            ParameterProb = ParameterProb/capture[no][IPv6]
        return(ParameterProb)

    ## Echo Request

    def BuildICMPv6_Ping(self):
        """This function creates a echo request message for the scapy code.
"""
        
        ping = ICMPv6EchoRequest(data=self.IPv6.ICMP['Message'])
        return(ping)

    ## Echo Reply

    def BuildICMPv6_EchoReply(self):
        """This function creates a echo reply message for the scapy code.
"""
        
        reply = ICMPv6EchoReply(data=self.IPv6.ICMP['Message'])
        return(reply)

    ## Multicast Listener Query

    def BuildICMPv6_MLQuery(self):
        """This function creates a Multicast Listener Query message for the scapy code.
"""
        return(ICMPv6MLQuery(mladdr=self.IPv6.ICMP['MLAddr'], mrd=int(self.IPv6.ICMP['MRD'])))

    ## Multicast Listener Report

    def BuildICMPv6_MLReport(self):
        """This function creates a Multicast Listener Report message for the scapy code.
"""
        return(ICMPv6MLReport(mladdr=self.IPv6.ICMP['MLAddr']))

    ## Multicast Listener Done

    def BuildICMPv6_MLDone(self):
        """This function creates a Multicast Listener Done message for the scapy code.
"""
        return(ICMPv6MLDone(mladdr=self.IPv6.ICMP['MLAddr']))

    ## Router Solicitation

    def BuildICMPv6_RS(self):
        """This function creates a router solicitation message for the scapy code.
"""
        return(ICMPv6ND_RS())

    ## Router Advertisement

    def BuildICMPv6_RA(self):
        """This function creates a router advertisment message for the scapy code.

It includes the M-/O-flag, router life time, current hop limit, prefix, prefixlength and optional the source link layer address.
This values are saved in the IPv6 array ``IPv6.RAconf``
"""

        if self.IPv6.RAconf['M'] == True: MFlag = 1
        else: MFlag = 0
        if self.IPv6.RAconf['O'] == True: OFlag = 1
        else: OFlag = 0
        ra=ICMPv6ND_RA(chlim=int(self.IPv6.RAconf['CHLim']), H=0L, M=MFlag, O=OFlag,
                       routerlifetime=int(self.IPv6.RAconf['RLTime']), P=0L, retranstimer=0, prf=0L,
                       res=0L)

        return(ra)

    ## Neighbor Solicitation

    def BuildICMPv6_NS(self):
        """This function creates a neighbor solicitation message for the scapy code.
"""
        ns = ICMPv6ND_NS(tgt=str(self.IPv6.NSconf['NS_tgtAddr']))
        return(ns)

    ## Neighbor Advertisment

    def BuildICMPv6_NA(self):
        """This function creates a router advertisment message for the scapy code.

It includes the R-/S-/O-flag and IPv6 target address.
This values are saved in the IPv6 array ``IPv6.NAconf``
"""
        if self.IPv6.NAconf['R'] == True: RFlag = 1
        else: RFlag = 0
        if self.IPv6.NAconf['S'] == True: SFlag = 1
        else: SFlag = 0
        if self.IPv6.NAconf['O'] == True: OFlag = 1
        else: OFlag = 0
        na = ICMPv6ND_NA(tgt=str(self.IPv6.NAconf['NA_tgtAddr']), R = RFlag, S = SFlag, O = OFlag)
        return(na)

    ## Redirect

    def BuildICMPv6_Redirect(self):
        """This function creates a Redirect message for the scapy code.

It includes the target and destination address.
"""
        return(ICMPv6ND_Redirect(tgt=str(self.IPv6.Redirect['Re_tgtAddr']), dst=str(self.IPv6.Redirect['Re_DstAddr'])))

    ## Inverse Neighbor Discovery Solicitation

    def BuildICMPv6_INDS(self):
        """This function builds an Inverse Neighbor Discovery Solicitation message.

A Inverse Neighbor Discovery Solicitation needs the Neighbor Discovery Options(ND Option):
    * Source Link-Layer Address,
    * Target Link-Layer Address,

and can optional includes the ND Option Source Address List and MTU.
"""
        return(ICMPv6ND_INDSol())

    ## Inverse Neighbor Discovery Advertisement

    def BuildICMPv6_INDS(self):
        """This function builds an Inverse Neighbor Discovery Advertisement message.

A Inverse Neighbor Discovery Advertisement needs the Neighbor Discovery Options(ND Option):
    * Source Link-Layer Address,
    * Target Link-Layer Address,
    * Target Address List,

and can optional includes the ND Option MTU.
"""
        return(ICMPv6ND_INDAdv())

    ## ICMP Unknown

    def BuildICMPv6_Unknown(self):
        """If you want to create an ICMP message which is not include yet, you need funktion ``BuildICMPv6_Unknown``. 
This function needs the type and the code from the ICMP message and optional informations for the message box.

.. note:: The information for the message box have to adapt for each ICMP message.

This values are saved in the IPv6 array ``IPv6.ICMP``
"""
        q = ICMPv6Unknown(type=int(self.IPv6.ICMP['Type']), code=int(self.IPv6.ICMP['Code']), msgbody=self.IPv6.ICMP['Message'])
        return(q)

    ## Neighbor Disvovery Options

    def BuildICMPv6_NDOpt(self, NextHeader):
        """This function adds Neightbor Discovery Options to the ICMPv6 typs 133, 134, 135, 136, 137, 141 and 142.
The options has to be choosen at the GUI.
"""
        if self.IPv6.NDOpt['Option'] & 1:
            sll = ICMPv6NDOptSrcLLAddr(lladdr=str(self.IPv6.NDOpt['ND_SrcLLAddr']))
            NextHeader = NextHeader/ sll
        if self.IPv6.NDOpt['Option'] & 2:
            dll = ICMPv6NDOptDstLLAddr(lladdr=str(self.IPv6.NDOpt['ND_DstLLAddr']))
            NextHeader = NextHeader/ dll
        if self.IPv6.NDOpt['Option'] & 4: 
            pre = ICMPv6NDOptPrefixInfo(L=self.IPv6.NDOpt['L'], A=self.IPv6.NDOpt['A'], 
                                        prefix=str(self.IPv6.NDOpt['Prefix']), 
                                        validlifetime=int(self.IPv6.NDOpt['ValidL']), 
                                        prefixlen=int(self.IPv6.NDOpt['Prefixlen']), 
                                        preferredlifetime=int(self.IPv6.NDOpt['PreferredL']))
            NextHeader = NextHeader/ pre
        if self.IPv6.NDOpt['Option'] & 8:
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            PCAPno = self.IPv6.Payload['Packet No.']
            if PCAPno != '':
                no = int(PCAPno)-1
            else:
                no = 0
            red = ICMPv6NDOptRedirectedHdr(pkt=capture[no][IPv6])
            NextHeader = NextHeader/ red
        if self.IPv6.NDOpt['Option'] & 16:
            mtu = ICMPv6NDOptMTU(mtu=int(self.IPv6.NDOpt['MTU']))
            NextHeader = NextHeader/ mtu
        if self.IPv6.NDOpt['Option'] & 32:
            sal = ICMPv6NDOptSrcAddrList(addrlist=self.IPv6.NDOpt['SrcAddrList'])
            NextHeader = NextHeader/ sal
        if self.IPv6.NDOpt['Option'] & 64:
            tal = ICMPv6NDOptTgtAddrList(addrlist=self.IPv6.NDOpt['TgtAddrList'])
            NextHeader = NextHeader/ tal        
        return (NextHeader)

    ## TCP

    def BuildTCP(self):
        """This function build a TCP header with source port, destination port and TCP flags.
It opens also the function ``BuildPayload`` and adds an optinal payload.
"""
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        tcp= TCP(sport=SPort, dport=DPort, flags=self.IPv6.TCP_UDP['Flags'])
        tcp = self.BuildPayload(tcp)
        return(tcp)

    ## UDP

    def BuildUDP(self):
        """This function build a UDP header with source port and destination port.
It opens also the function ``BuildPayload`` and adds an optinal payload.
"""
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        udp= UDP(sport=SPort, dport=DPort)
        udp = self.BuildPayload(udp)
        return(udp)

    ## No Next Header

    def BuildNoNextHeader(self):
        """This function is used, if no next header is chosen.
"""
        return(None)

    ## Payload

    def BuildPayload(self, x):
        """The ``BuildPayload`` function identify the payload option and adds this payload to the next header.

    :param x: previously defined next header
"""
        if self.IPv6.Payload['indizeP'] == 3:
            return(x)
        elif self.IPv6.Payload['indizeP'] == 0:
            load = 'X'*int(self.IPv6.Payload['Payloadlen'])
            return(x/load)
        elif self.IPv6.Payload['indizeP'] == 1:
            load = str(self.IPv6.Payload['PayloadString'])
            return(x/load)
        elif self.IPv6.Payload['indizeP'] == 2:
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            PCAPno = self.IPv6.Payload['Packet No.']
            if PCAPno != '':
                no = int(PCAPno)-1
            else:
                no = 0
            load = capture[no][Raw]
            return(x/load)
