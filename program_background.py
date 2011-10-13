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

class IPv6Paket:
    """Dient dem Erstellen eines IPv6 Arrays, welches notwenige Informationen zur Packertgenerierung enthält.

    Es werden nie alle Werte benötigt.

    :returns: -- EthHdr -- Ethernet Header (link-layer source address, -destination address, Interface)

              -- IPHdr  -- IPv6 Header (source and destination IPv6 address)

              -- indize -- int Wert zur Erkennung des Next Headers:: 

                        0 = ICMP
                        1 = TCP
                        2 = UDP
                        3 = no Next Header

              -- RAconf -- Router Advertisement (Prefix, Prefix Length, link-layer source address, M and O Flag, Router Life Time, Cur Hop Limit)

              -- NAconf -- Neighbor Advertisement (Target IPv6 address, Flags)

              -- NSconf -- Neighbor Solicitation (link-layer source address)

              -- ICMP   -- Internet Control Message Protocol (Code, Type, Message, indize)
                            -- indize -- int Wert zur Erkennung des ICMP Types:: 

                                0 = Ping
                                1 = Router Advertisement
                                2 = Router Solicitation 
                                3 = Neighbor Advertisement
                                4 = Neighbor Solicitation
                                5 = Paket Too Big
                                6 = other Type

              -- PTB    -- ICMP Paket too big (MTU)

              -- TCP_UDP -- Transmission Control and User Datagram Protocol (source and destination Port, TCP-Flags)

              -- Payload -- Payload Info (Payload Length, Payload String, Capture File, File no., indizeP )
                            -- indizeP -- int Wert zur Erkennung der Payload Variante::

                                0 = String wiht 'X' * len
                                1 = String
                                2 = pcap File
                                3 = no Payload
    
    """
    EthHdr = {'LLSrcAddr': None, 'LLDstAddr': None, 'Interface': None}
    IPHdr = {'SrcIPAddr': None, 'DstIPAddr': None}
    ExtHdr = [['','','','']]
    indize = 0
    RAconf = {'Prefix':'fd00:141:64:1::','Prefixlen':'64','RA_LLSrcAddr':'', 'M': False, 'O': False, 'RouterLifeTime':'1800', 'CHLim': '255'}
    NSconf = {'NS_LLSrcAddr': ':::::'}
    NAconf = {'NA_tgtAddr': '::', 'R' : True, 'S' : False, 'O' : True}
    ICMP = {'indize': 0, 'Code': '1', 'Type': '0', 'Message': ''}
    PTB = {'MTU': '1280'}
    TCP_UDP = {'SrcPort': '20', 'DstPort': '80', 'Flags': 2}
    Payload = {'indizeP': 0, 'Payloadlen': '1', 'PayloadString': 'X', 'Capture File': '', 'Packet No.': '1'}
  
'''
class GetIPv6Addr():
    """Diese Funktion enthält ein Werkzeug, mit dessen Hilfe die lokalen IPv6 Addressen ermittelt und in die entsprechende ComboBox hizugefügt werden."""
    def __init__(self):
        query = Ether()/IPv6(dst='ff02::1',hlim=1)/IPv6ExtHdrHopByHop(autopad=0,nh=58)/ICMPv6MLQuery()
        query[2].options='\x05\x02\x00\x00\x00\x00'
        sendp(query)
        ans=sniff(filter='ip6[48]=131', timeout=10)
        addresses=[]
        request = Ether()/IPv6(dst='ff02::1')/ICMPv6EchoRequest()
        ans2 = srp(request, multi = 1, timeout = 10)
        if ans != None:
            for paket in ans:
                addresses.append(paket[IPv6].src)
        if ans2 != None:
            for paket in ans2[0]:
                addresses.append(paket[1][IPv6].src)
        uniqueAddr = set(addresses)
        return(uniqueAddr)'''

class Buildit:
    """Diese Klasse erstellt das IPv6 Packet in Scapy Format und Verarbeitet es je nach Option weiter.
    
    :param Option: Mögliche Optionen für die Weiterverarbeitung
    :type Option: int 
    :param File: Pfad zum Speichern in einer pcap-Datei
    :type File: file
    :param IPv6Paket: IPv6 Packet mit Packetinformationen
    :type IPv6Paket: class.IPv6Paket

    Optionen::

            0 -- Senden
            1 -- Speichern als *.pcap 
            2 -- Speichern im Zwischenspeicher

    """
    
    def __init__(self,Option, File, IPv6Paket):

        self.IPv6 = IPv6Paket
        self.IPv6packet = {'EthHeader':None,'IPHeader':None,
                           'ExtHeader':None,'NextHeader':None}
        self.IPv6Scapy = None

        ##################
        ## Ethernet Header

        self.IPv6packet['EthHeader'] = Ether(dst=self.IPv6.EthHdr['LLDstAddr'],
                                             src=self.IPv6.EthHdr['LLSrcAddr'])

        ##############
        ## IPv6 Header

        self.IPv6packet['IPHeader'] = IPv6(dst=self.IPv6.IPHdr['DstIPAddr'],
                                           src=self.IPv6.IPHdr['SrcIPAddr'])

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
        ## send or save (pcap og Clipbord)
		
        if self.IPv6packet['ExtHeader'] == (None or '') and self.IPv6packet['NextHeader'] != None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['NextHeader'])
        elif self.IPv6packet['ExtHeader'] == (None or '') and self.IPv6packet['NextHeader'] == None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader'])
        elif self.IPv6packet['ExtHeader'] != (None or '') and self.IPv6packet['NextHeader'] != None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader']/self.IPv6packet['NextHeader'])
        elif self.IPv6packet['ExtHeader'] != (None or '') and self.IPv6packet['NextHeader'] == None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader'])
    

        if Option == 0:
            ## send
            sendp(self.IPv6Scapy, iface = Interface)
                
        elif Option == 1:
            ## save as .pcap
			
            wrpcap(File, self.IPv6Scapy)
                
        else:
            ## save to Clipboard
            Clipboard = QtGui.QApplication.clipboard()
            Clipboard.setText(self.IPv6Scapy.command())

        ## show sourcecode
        disp_sourcecode = QtGui.QMessageBox.information(None, "Scapy Quellcode", "Scapy Quellcode:\n\n%s" % self.IPv6Scapy.command() )

    ###############
    ## Build Extension Header

    def  BuildExtHdr(self, Num):
        """Erstellen der Extension Header im Scapycode.
        
        :param Num: Anzahl der Extension Header
        :type Num: int

        """
        ExtensionHeader = ''
        for d in range(Num):
            if self.IPv6.ExtHdr[d][0] == 'Hop By Hop Options':
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrHopByHop()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrHopByHop()
            elif self.IPv6.ExtHdr[d][0] == 'Destination Options':
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrDestOpt()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrDestOpt()
            elif self.IPv6.ExtHdr[d][0] == 'Routing':
                i = len(self.IPv6.ExtHdr[d][1])
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
        return(ExtensionHeader)

    ###############
    ## Build Next Header

    def BuildNextHeader(self):
        """Auswahl des richtigen Next Header Protokolls anhand des ``IPv6.indize`` für den Next Header Type und ``IPv6.ICMP['indize']`` für den richtigen ICMP Type (bei ``IPv6.indize == 0``).
        
        Nach Auswahl des richtigen Next Header Protokolls wird eine entsprechende Funktion augerufen.

        ``IPv6.indize``::
            
             0 = ICMP
             1 = TCP
             2 = UDP
             3 = no Next Header

        ``IPv6.ICMP['indize']``::

             0 = Ping
             1 = Router Advertisement
             2 = Router Solicitation 
             3 = Neighbor Advertisement
             4 = Neighbor Solicitation
             5 = Paket Too Big
             6 = other Type
        """

        if self.IPv6.indize == 0:               # ICMP
            if self.IPv6.ICMP['indize'] == 0:        # Ping
                NextHeader = self.BuildICMPv6_Ping()
            elif self.IPv6.ICMP['indize'] == 1:      # Router Advetisement
                NextHeader = self.BuildICMPv6_RA()
            elif self.IPv6.ICMP['indize'] == 2:      # Router Solicitation
                NextHeader = self.BuildICMPv6_RS()
            elif self.IPv6.ICMP['indize'] == 3:      # Neighbor Advetisement
                NextHeader = self.BuildICMPv6_NA()
            elif self.IPv6.ICMP['indize'] == 4:      # Neighbor Solicitation
                NextHeader = self.BuildICMPv6_NS()
            elif self.IPv6.ICMP['indize'] == 5:      # Packet Too Big
                NextHeader = self.BuildICMPv6_PacketTooBig()
            elif self.IPv6.ICMP['indize'] == 6:      # ICMP Unknown
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
        return(ICMPv6EchoRequest())

    ## Router Solicitation

    def BuildICMPv6_RS(self):
        rs = ICMPv6ND_RS()
        return(rs)

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
            return(ra/prefix_info/llad)
        else:
            return(ra/prefix_info)

    ## Neighbor Solicitation

    def BuildICMPv6_NS(self):

        ns = ICMPv6ND_NS(tgt=str(self.IPv6.NSconf['NS_LLSrcAddr']))
        return(ns)

    ## Neighbor Advertisment

    def BuildICMPv6_NA(self):

        if self.IPv6.NAconf['R'] == True: RFlag = 1
        else: RFlag = 0
        if self.IPv6.NAconf['S'] == True: SFlag = 1
        else: SFlag = 0
        if self.IPv6.NAconf['O'] == True: OFlag = 1
        else: OFlag = 0
        na = ICMPv6ND_NA(tgt=str(self.IPv6.NAconf['NA_tgtAddr']), R = RFlag, S = SFlag, O = OFlag)
        return(na)

    ## Packet Too Big

    def BuildICMPv6_PacketTooBig(self):

        if self.IPv6.PTB['MTU'] != '':
            MTU = self.IPv6.PTB['MTU']
        else:
            MTU = None
        q = ICMPv6PacketTooBig(mtu=int(MTU))

        if self.IPv6.Payload['Capture File'] != '':
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            enPCAPno = self.PayloadFile['Packet No.']
            if self.IPv6.Payload['Packet No.'] != '':
                no = int(self.IPv6.Payload['Packet No.'])-1
            else:
                no = 0
            q = q/capture[no][IPv6]
        return(q)

    ## ICMP Unknown

    def BuildICMPv6_Unknown(self):

        q = ICMPv6Unknown(type=int(self.IPv6.ICMP['Type']), code=int(self.IPv6.ICMP['Code']), msgbody=self.IPv6.ICMP['Message'])
        return(q)

    ## TCP

    def BuildTCP(self):
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        tcp= TCP(sport=SPort, dport=DPort, flags=self.IPv6.TCP_UDP['Flags'])
        tcp = self.BuildPayload(tcp)
        return(tcp)

    ## UDP

    def BuildUDP(self):
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        udp= UDP(sport=SPort, dport=DPort)
        udp = self.BuildPayload(udp)
        return(udp)

    ## No Next Header

    def BuildNoNextHeader(self):
        return(None)

    ## Payload

    def BuildPayload(self, x):
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
