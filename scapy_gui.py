#!/usr/bin/env python
#-*- coding: utf-8 -*-

######################################################
##
## 2.0
##
######################################################

import gtk
from scapy.all import *


class MyApp(object):
    def __init__(self):
        self.builder = gtk.Builder()
        self.builder.add_from_file("scapy_gui.glade")
        self.builder.connect_signals(self)
        self.win =  self.builder.get_object('window1')
        self.path = None

        self.EthH = {'LLSourceAddr':None,'LLDstAddr':None}
        self.IPH = {'Dst':None,'SourceIP':None,'RoutingHdr':None,'NextHeader':None}
        self.ICMP = {'Type':'128'}
        self.RAconf = {'Prefix':None,'Prefixlen':None,'SourceLL':None}
        self.IPv6packet = {'EthHeader':'None','IPHeader':None,'NextHeader':None}

        self.sourcecode = None ## var to display the sourcecode 

        ## init cbIface
        iflist = get_if_list()
        cbIface = self.builder.get_object('cbIface')
        ifListStore=gtk.ListStore(str)
        for d in iflist:
            ifListStore.append([d])
        cbIface.set_model(ifListStore)
        cbIface.set_text_column(0)

        ## init cbSrcLLaddr
        i = len(iflist)
        ifLLaddrList=[]
        for d in range(0, i):
            ifLLaddrList.append(get_if_hwaddr(iflist[d]))

        LLaddrList=gtk.ListStore(str)
        for d in ifLLaddrList:
            LLaddrList.append([d])
        cbSrcLLaddr = self.builder.get_object('cbSrcLLaddr')
        cbSrcLLaddr.set_model(LLaddrList)
        cbSrcLLaddr.set_text_column(0)

        ## init cbDlgRASourceLL
        cbDlgRASourceLL = self.builder.get_object('cbDlgRASourceLL')
        cbDlgRASourceLL.set_model(LLaddrList)
        cbDlgRASourceLL.set_text_column(0)


    def run(self):
        try:
            gtk.main()
        except KeyboardInterrupt:
            pass
    
    def quit(self):
        gtk.main_quit()
    

    def ask_for_filename(self, title, default=None):
        dlg = gtk.FileChooserDialog(title=title,
                                    parent=self.win, 
                                    buttons=(gtk.STOCK_CANCEL,
                                             gtk.RESPONSE_REJECT,
                                             gtk.STOCK_OK,
                                             gtk.RESPONSE_OK))

        if default is not None:
            dlg.set_filename(default)

        result = dlg.run()

        if result == gtk.RESPONSE_OK:
            path = dlg.get_filename()
        else:
            path = None

        dlg.destroy()
        return path


##################
## Message Dialogs
##################

## info msg
    def info_msg(self, msg):
        dlg = gtk.MessageDialog(parent=self.win, 
                                type=gtk.MESSAGE_INFO, 
                                buttons=gtk.BUTTONS_OK,
                                message_format=msg
                                )
        dlg.run()
        dlg.destroy()

## error msg
    def err_msg(self, msg):
        dlg = gtk.MessageDialog(parent=self.win, 
                                type=gtk.MESSAGE_ERROR, 
                                buttons=gtk.BUTTONS_OK,
                                message_format=msg
                                )
        dlg.run()
        dlg.destroy()


#################
## event handling
#################

##################
## set global vars

    def SetICMPv6Type(self,Type):
        self.ICMP['Type'] = Type

    def SetRAconf(self):
        dlg = self.builder.get_object('dlgRAconf')
        result = dlg.run()
        dlg.hide()
        if result == 0:
            enDlgRAPrefix = self.builder.get_object('enDlgRAPrefix')
            self.RAconf['Prefix'] = enDlgRAPrefix.get_text()
            enDlgRAPrefixlen = self.builder.get_object('enDlgRAPrefixlen')
            self.RAconf['Prefixlen'] = enDlgRAPrefixlen.get_text()
            cbDlgRASourceLL = self.builder.get_object('cbDlgRASourceLL')
            self.RAconf['SourceLL'] = cbDlgRASourceLL.child.get_text()
            if ((self.RAconf['Prefix'] == '' or None) or 
                (self.RAconf['Prefixlen'] == '' or None)):
                self.err_msg('Prefix and Prefix length are requiered!')
        else:
            self.err_msg('These settings are required!')
        

###################
## build ip packets

    def Buildit(self):

        ##################
        ## Ethernet Header

        enDstLLaddr = self.builder.get_object('enDstLLaddr')

        if enDstLLaddr.get_text() != '':
            self.EthH['LLDstAddr'] = enDstLLaddr.get_text()
        else:
            self.EthH['LLDstAddr'] = None

        cbSrcLLaddr = self.builder.get_object('cbSrcLLaddr')

        if cbSrcLLaddr.child.get_text() != '':
            self.EthH['LLSourceAddr'] = cbSrcLLaddr.child.get_text()
        else:
            self.EthH['LLSourceAddr'] = None

        self.IPv6packet['EthHeader'] = Ether(dst=self.EthH['LLDstAddr'],
                                             src=self.EthH['LLSourceAddr'])

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

        enDstIP =  self.builder.get_object('enDstIP')
        if enDstIP.get_text() != '':
            self.IPH['Dst'] = enDstIP.get_text()
        else:
            self.IPH['Dst'] = None

        enSourceIP =  self.builder.get_object('enSourceIP')
        if enSourceIP.get_text() != '':
            self.IPH['SourceIP'] = enSourceIP.get_text()
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
        ## add routing header if set

        enRtgHops = self.builder.get_object('enRtgHops')
        if enRtgHops.get_text() != '':
            self.IPH['RoutingHdr'] = IPv6ExtHdrRouting(addresses=
                                                       [enRtgHops.get_text()])
            self.sourcecode = (self.sourcecode+
                               '/IPv6ExtHdrRouting(addresses=['+
                               enRtgHops.get_text()+'])')
        else:
            self.IPH['RoutingHdr'] = None

        ########################
        ## add the next header

        self.IPv6packet['NextHeader'] = self.BuildICMPv6()

        ############
        ## get iface

        cbIface =  self.builder.get_object('cbIface')
        if cbIface.child.get_text() != '':
            Interface = cbIface.child.get_text()
        else:
            Interface = None

        ##########
        ## send it

        if self.IPH['RoutingHdr'] == None:
            sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                  /self.IPv6packet['NextHeader'], iface = Interface)
        else:
            sendp(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']
                  /self.IPH['RoutingHdr']/self.IPv6packet['NextHeader'],
                  iface = Interface)

        ## show sourcecode in info_msg:
        if Interface == None:
            self.sourcecode = 'sendp('+self.sourcecode+')'
        else:
            self.sourcecode = ('sendp('+self.sourcecode+
                               ', iface=\''+str(Interface)+'\')')
        self.info_msg('Scapy Quellcode:\n\n'+self.sourcecode)

    ###############
    ## Build ICMPv6

    def BuildICMPv6(self):

        if self.ICMP['Type'] == '128':
            ICMPv6 = self.BuildICMPv6_Ping()
        elif self.ICMP['Type'] == '134':
            ICMPv6 = self.BuildICMPv6_RA()
        elif self.ICMP['Type'] == '2':
            ICMPv6 = self.BuildICMPv6_PacketTooBig()
        else:
            self.err_msg('Sorry ICMPv6 Type %s is not implemented yet.'
                         %self.ICMP['Type'])

        return(ICMPv6)

    ## Router Advertisement

    def BuildICMPv6_RA(self):

        ra=ICMPv6ND_RA(chlim=255, H=0L, M=0L, O=1L,
                       routerlifetime=180, P=0L, retranstimer=0, prf=0L,
                       res=0L)

        prefix_info=ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L,
                                          len=4,
                                          prefix=self.RAconf['Prefix'],
                                          R=0L, validlifetime=1814400,
                                          prefixlen=int(self.RAconf['Prefixlen']),
                                          preferredlifetime=604800, type=3)

        ## if source link-layer-addr set

        if (self.RAconf['SourceLL'] != None) and (self.RAconf['SourceLL'] != ''):
            llad=ICMPv6NDOptSrcLLAddr(type=1, len=1,
                                      lladdr=self.RAconf['SourceLL'])

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
                               'lladdr='+self.RAconf['SourceLL']+')')
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
        q=ICMPv6EchoRequest()
        self.sourcecode = self.sourcecode+'/ICMPv6EchoRequest()'
        return(q)

    ## Packet Too Big

    def BuildICMPv6_PacketTooBig(self):

        enMTU = self.builder.get_object('enMTU')
        if enMTU.get_text() != '':
            MTU = enMTU.get_text()
        else:
            MTU = None
        q=ICMPv6PacketTooBig(mtu=int(MTU))
        self.sourcecode = self.sourcecode+'/ICMPv6PacketTooBig(mtu='+MTU+')'

        enPCAP = self.builder.get_object('enPCAP')
        if enPCAP.get_text() != '':
            path = enPCAP.get_text()
            capture = rdpcap(path)
            enPCAPno = self.builder.get_object('enPCAPno')
            if enPCAPno.get_text() != '':
                no = int(enPCAPno.get_text())-1
            else:
                no = 0
            q = q/capture[no][IPv6]
            self.sourcecode = (self.sourcecode+'/rdpcap(\''+path+'\')['+
                               str(no)+'][IPv6]')
        return(q)


###############
## GUI - events
###############

    def on_window1_delete_event(self, *args):
        self.quit()


##########
## window1

    def on_act_quit_activate(self, *args):
        self.quit()

    def on_act_info_activate(self, *args):
        self.info_msg('Info')

    def on_act_open_activate(self, *args):
        path = self.ask_for_filename('Datei öffnen', self.path)
        if path is None:
            self.info_msg('Keine Datei ausgewählt')
        else:
            self.path = path
            self.info_msg('Datei "%s" ausgewählt.'%self.path)

    def on_btsend_clicked(self, *args):
        self.Buildit()


##############
## IPv6 Header

##############
## Next Header

    def on_rbNhICMPv6_toggled(self, button, *args):
        if button.get_active():
            self.IPH['NextHeader'] = 'ICMPv6'

    def on_rbNhOther_toggled(self, button, *args):
        if button.get_active():
            self.IPH['NextHeader'] = 'Other'


#################
## ICMPv6 Options

    ## get ICMPv6 type from entry if changed
    def on_enICMPv6Type_changed(self, *args):
        enICMPv6Type = self.builder.get_object('enICMPv6Type')
        self.SetICMPv6Type(enICMPv6Type.get_text())

    ## get ICMPv6 type from radio buttons
    def on_rbPing_toggled(self, button, *args):
        if  button.get_active():
            self.SetICMPv6Type('128') ## Echo Request

    def on_rbRA_toggled(self, button, *args):
        if  button.get_active():
            self.SetICMPv6Type('134') ## Router Advertisement

    def on_rbRA_clicked(self, button, *args):
        if  button.get_active():
            self.SetRAconf()

    def on_rbTooBig_toggled(self, button, *args):
        if  button.get_active():
            self.SetICMPv6Type('2') ## Packet Too Big
            self.info_msg('Advanced settings are requiered\n'+
                          'to create a valid package.')


##############
## advanced...

    ## get capturefile
    def on_btOpcap_clicked(self, *args):
        path = self.ask_for_filename('Open File', self.path)
        if path is None:
            self.info_msg('Please select a File.')
        else:
            enPCAP = self.builder.get_object('enPCAP')
            enPCAP.set_text(path)


if __name__ == '__main__':
    app = MyApp()
    app.run()
