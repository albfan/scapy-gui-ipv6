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

class IPv6Paket:

    EthHdr = {'LLSrcAddr': None, 'LLDstAddr': None, 'Interface': None}
    IPHdr = {'SrcIPAddr': None, 'DstIPAddr': None}
    ExtHdr = [['','','','']]
    indize = 0
    # indize: 0 = ICMP, 1 = TCP, 2 = UDP, 3 = no Next Header
    RAconf = {'Prefix':'fd00:141:64:1::','Prefixlen':'64','RA_LLSrcAddr':'', 'M': False, 'O': False, 'RouterLifeTime':'1800', 'CHLim': '255'}   # Router Advetisement
    NSconf = {'NS_LLSrcAddr': '::'} # Neighbor Solicitation
    ICMP = {'indize': 0, 'Code': '1', 'Type': '0', 'Message': ''}
    # indize: 0 = Ping, 1 = Neighbor Solicitation, 2 = Router Advertisement, 3 = Paket Too Big, 4 = other Type
    PTB = {'MTU': '1280'} # ICMP Paket too big
    TCP_UDP = {'SrcPort': '20', 'DstPort': '80', 'Flags': 2}
    Payload = {'indizeP': 0, 'Payloadlen': '1', 'PayloadString': 'X', 'Capture File': '', 'Packet No.': '1'}	# Payload information
    # indizeP: 0 = String wiht 'X' * len, 1 = String, 2 = pcap File, 3 = no Payload
    

class Buildit:
    
    def __init__(self,Type, File, IPv6Paket):

        self.sourcecode = None ## var to display the sourcecode 
        self.IPv6 = IPv6Paket
        self.IPv6packet = {'EthHeader':None,'IPHeader':None,
                           'ExtHeader':None,'NextHeader':None}

        ##################
        ## Ethernet Header

        self.IPv6packet['EthHeader'] = Ether(dst=self.IPv6.EthHdr['LLDstAddr'],
                                             src=self.IPv6.EthHdr['LLSrcAddr'])

			## sourcecode...
        if ((self.IPv6.EthHdr['LLDstAddr'] != None ) and (self.IPv6.EthHdr['LLSrcAddr'] != None)):
            self.sourcecode = ('Ether(dst=\''+str(self.IPv6.EthHdr['LLDstAddr'])+
                               '\', src=\''+str(self.IPv6.EthHdr['LLSrcAddr'])+'\')')
        elif (self.IPv6.EthHdr['LLDstAddr'] != None):
            self.sourcecode = ('Ether(dst=\''+str(self.IPv6.EthHdr['LLDstAddr'])+'\')')
        elif (self.IPv6.EthHdr['LLSrcAddr'] != None):
            self.sourcecode = ('Ether(src=\''+str(self.IPv6.EthHdr['LLSrcAddr'])+'\')')
        elif ((self.IPv6.EthHdr['LLDstAddr'] == None) and (self.IPv6.EthHdr['LLSrcAddr'] == None)):
            self.sourcecode = ('Ether()')

        ##############
        ## IPv6 Header

        self.IPv6packet['IPHeader'] = IPv6(dst=self.IPv6.IPHdr['DstIPAddr'],
                                           src=self.IPv6.IPHdr['SrcIPAddr'])

			## sourcecode...
        if (self.IPv6.IPHdr['SrcIPAddr'] != None):
            self.sourcecode = (self.sourcecode+'/IPv6(dst=\''+self.IPv6.IPHdr['DstIPAddr']+
                               '\', src=\''+self.IPv6.IPHdr['SrcIPAddr']+'\')')
        elif (self.IPv6.IPHdr['SrcIPAddr'] == None):
            self.sourcecode = (self.sourcecode+'/IPv6(dst=\''+self.IPv6.IPHdr['DstIPAddr']+
                               '\')')

        ############################
        ## add extension header if set

        self.NumExtHdr = len(self.IPv6.ExtHdr)
        if self.NumExtHdr > 0:
            self.IPv6packet['ExtHeader'] = self.BuildExtHdr(self.NumExtHdr)
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

        ############
        ## Create Sourcecode
		
        x = self.sourcecode
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
                    wrpcap(File, self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['NextHeader'])
                else:
                    wrpcap(File, self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader'])
            else:
                if self.IPv6packet['NextHeader'] != None:
                    wrpcap(File, self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader']/self.IPv6packet['NextHeader'])
                else:
                    wrpcap(File, self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader'])
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
            if self.IPv6.ExtHdr[d][0] == 'Hop By Hop Options':
                self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrHopByHop()')
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrHopByHop()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrHopByHop()
            elif self.IPv6.ExtHdr[d][0] == 'Destination Options':
                self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrDestOpt()')
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrDestOpt()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrDestOpt()
            elif self.IPv6.ExtHdr[d][0] == 'Routing':
                i = len(self.IPv6.ExtHdr[d][1])
                if (self.IPv6.ExtHdr[d][1][0] != '' or None):
                    self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrRouting(addresses=[\'' + self.IPv6.ExtHdr[d][1][0])
                    if i > 1:
                        for d2 in range(i-1):
                            self.sourcecode = (self.sourcecode + '\',\'' +
                                               self.IPv6.ExtHdr[d][1][d2+1])
                self.sourcecode = (self.sourcecode + '\'])')
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrRouting(addresses = self.IPv6.ExtHdr[d][1])
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrRouting(addresses = self.IPv6.ExtHdr[d][1])
            elif self.IPv6.ExtHdr[d][0] == 'Fragmentation':
                if self.IPv6.ExtHdr[d][3] == 0:
                    self.M_Flag = '0'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.IPv6.ExtHdr[d][3], offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 0, offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                else:
                    self.M_Flag = '1'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.IPv6.ExtHdr[d][3], offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 1, offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                self.sourcecode = (self.sourcecode + ' /IPv6ExtHdrFragment(m=' + 
                                  str(self.M_Flag) + ',offset=' + 
                                  str(self.IPv6.ExtHdr[d][1]) + ',id=' + 
                                  str(self.IPv6.ExtHdr[d][2]) + ')')
        return(ExtensionHeader)

    ###############
    ## Build Next Header

    def BuildNextHeader(self):

        if self.IPv6.indize == 0:               # ICMP
            if self.IPv6.ICMP['indize'] == 0:        # Ping
                NextHeader = self.BuildICMPv6_Ping()
            elif self.IPv6.ICMP['indize'] == 1:      # Neighbor Solicitation
                NextHeader = self.BuildICMPv6_NS()
            elif self.IPv6.ICMP['indize'] == 2:      # Router Advetisement
                NextHeader = self.BuildICMPv6_RA()
            elif self.IPv6.ICMP['indize'] == 3:      # Packet Too Big
                NextHeader = self.BuildICMPv6_PacketTooBig()
            elif self.IPv6.ICMP['indize'] == 4:      # ICMP Unknown
                NextHeader = self.BuildICMPv6_Unknown()
        elif self.IPv6.indize == 1:             # TCP
            NextHeader = self.BuildTCP()
        elif self.IPv6.indize == 2:             # UDP
            NextHeader = self.BuildUDP()
        elif self.IPv6.indize == 3:             # No Next Header
            NextHeader = self.BuildNoNextHeader()
        else:
            self.Fehler = QtGui.QMessageBox.information(None, '', 'Sorry this Next Header is not implemented yet.')

        return(NextHeader)

    ## Echo Request

    def BuildICMPv6_Ping(self):
        self.sourcecode = self.sourcecode+'/ICMPv6EchoRequest()'
        return(ICMPv6EchoRequest())

    ## Neighbor Solicitation

    def BuildICMPv6_NS(self):

        ns = ICMPv6ND_NS(tgt=self.IPv6.NSconf['NS_LLSrcAddr'])
        self.sourcecode = (self.sourcecode+'/ICMPv6ND_NS(tgt=\''+self.IPv6.NSconf['NS_LLSrcAddr']+'\')')
        return(ns)


    ## Router Advertisement

    def BuildICMPv6_RA(self):

        if self.IPv6.RAconf['M'] == True: MFlag = 1
        else: MFlag = 0
        if self.IPv6.RAconf['O'] == True: OFlag = 1
        else: OFlag = 0
        ra=ICMPv6ND_RA(chlim=int(self.IPv6.RAconf['CHLim']), H=0L, M=MFlag, O=OFlag,
                       routerlifetime=int(self.IPv6.RAconf['RouterLifeTime']), P=0L, retranstimer=0, prf=0L,
                       res=0L)

        prefix_info=ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L,
                                          len=4,
                                          prefix=str(self.IPv6.RAconf['Prefix']),
                                          R=0L, validlifetime=1814400,
                                          prefixlen=int(self.IPv6.RAconf['Prefixlen']),
                                          preferredlifetime=604800, type=3)

        ## if source link-layer-addr set

        if (self.IPv6.RAconf['RA_LLSrcAddr'] != (None or '')):
            llad=ICMPv6NDOptSrcLLAddr(type=1, len=1,
                                      lladdr=str(self.IPv6.RAconf['RA_LLSrcAddr']))

            self.sourcecode = (self.sourcecode+
                               '/ICMPv6ND_RA(chlim='+self.IPv6.RAconf['CHLim']+', H=0L, M='+
                               str(MFlag)+', O='+str(OFlag)+', routerlifetime='+
                               self.IPv6.RAconf['RouterLifeTime']+
                               ', P=0L, retranstimer=0, prf=0L, res=0L)'+
                               '/ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, '+
                               'L=1L, len=4, '+
                               'prefix=\''+self.IPv6.RAconf['Prefix']+'\', '+
                               'R=0L, validlifetime=1814400, '+
                               'prefixlen='+self.IPv6.RAconf['Prefixlen']+', '+
                               'preferredlifetime=604800, type=3)'+
                               '/ICMPv6NDOptSrcLLAddr(type=1, len=1, '+
                               'lladdr=\''+self.IPv6.RAconf['RA_LLSrcAddr']+'\')')
            return(ra/prefix_info/llad)
        else:
            self.sourcecode = (self.sourcecode+
                               '/ICMPv6ND_RA(chlim='+self.IPv6.RAconf['CHLim']+', H=0L, M='+
                               str(MFlag)+', O='+str(OFlag)+', routerlifetime='+
                               self.IPv6.RAconf['RouterLifeTime']+
                               'P=0L, retranstimer=0, prf=0L, res=0L)'+
                               '/ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, '+
                               'L=1L, len=4, '+
                               'prefix=\''+self.IPv6.RAconf['Prefix']+'\', '+
                               'R=0L, validlifetime=1814400, '+
                               'prefixlen='+self.IPv6.RAconf['Prefixlen']+', '+
                               'preferredlifetime=604800, type=3)')
            return(ra/prefix_info)

    ## Packet Too Big

    def BuildICMPv6_PacketTooBig(self):

        if self.IPv6.PTB['MTU'] != '':
            MTU = self.IPv6.PTB['MTU']
        else:
            MTU = None
        q = ICMPv6PacketTooBig(mtu=int(MTU))
        self.sourcecode = self.sourcecode+' /ICMPv6PacketTooBig(mtu='+MTU+')'

        if self.IPv6.Payload['Capture File'] != '':
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            enPCAPno = self.PayloadFile['Packet No.']
            if self.IPv6.Payload['Packet No.'] != '':
                no = int(self.IPv6.Payload['Packet No.'])-1
            else:
                no = 0
            q = q/capture[no][IPv6]
            self.sourcecode = (self.sourcecode+' /rdpcap(\''+path+'\')['+
                               str(no)+'][IPv6]')
        return(q)

    ## ICMP Unknown

    def BuildICMPv6_Unknown(self):

        q = ICMPv6Unknown(type=int(self.IPv6.ICMP['Type']), code=int(self.IPv6.ICMP['Code']), msgbody=self.IPv6.ICMP['Message'])
        self.sourcecode = self.sourcecode+' /ICMPv6Unknown(type='+self.IPv6.ICMP['Type']+',code='+self.IPv6.ICMP['Code']+',msgbody=\''+self.IPv6.ICMP['Message']+'\')'
        return(q)

    ## TCP

    def BuildTCP(self):
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        tcp= TCP(sport=SPort, dport=DPort, flags=self.IPv6.TCP_UDP['Flags'])
        self.sourcecode = self.sourcecode+'/TCP(sport='+str(SPort)+', dport='+str(DPort)+', flags='+str(self.IPv6.TCP_UDP['Flags'])+')'
        tcp = self.BuildPayload(tcp)
        return(tcp)

    ## UDP

    def BuildUDP(self):
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        udp= UDP(sport=SPort, dport=DPort)
        self.sourcecode = self.sourcecode+'/UDP(sport='+str(SPort)+' ,dport='+str(DPort)+')'
        udp = self.BuildPayload(udp)
        return(udp)

    ## No Next Header

    def BuildNoNextHeader(self):
        self.sourcecode = self.sourcecode
        return(None)

    ## Payload

    def BuildPayload(self, x):
        if self.IPv6.Payload['indizeP'] == 3:
            return(x)
        elif self.IPv6.Payload['indizeP'] == 0:
            load = 'X'*int(self.IPv6.Payload['Payloadlen'])
            self.sourcecode = self.sourcecode+'/\'X\'*'+self.IPv6.Payload['Payloadlen']
            return(x/load)
        elif self.IPv6.Payload['indizeP'] == 1:
            load = str(self.IPv6.Payload['PayloadString'])
            self.sourcecode = self.sourcecode+'/\''+self.IPv6.Payload['PayloadString']+'\''
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
            self.sourcecode = (self.sourcecode+' /rdpcap(\''+path+'\')['+
                               str(no)+'][Raw]')
            return(x/load)
