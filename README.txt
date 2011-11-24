#########################################################################
##                                                                      #
## scapy-gui-ipv6 (A GUI for IPv6 Packetgeneration with Scapy)          #
##                                                                      #
#########################################################################
##                                                                      #
<<<<<<< .mine
## Version: 2.2                                                         #
## Date:    23.11.2011                                                  #
=======
## Version: 2.1                                                         #
## Date:    10.11.2011                                                  #
>>>>>>> .r37
##                                                                      #
#########################################################################

DESCRIPTION:

This tool provides a GUI for the Python network tool Scapy.

It serves as a learning tool for packet generation with Python and as a 
tool for rapid IPv6 packet generation.


INSTALLATION:

You can simply download the current version from here: 
http://code.google.com/p/scapy-gui-ipv6/downloads/list

Unzip and run the included Python 'gui.py' script as root or 
using 'sudo'. Extended privileges are only required if the
GUI is used to actually send packets to the network. It can
be run by any non-priviledged users in order to build 
Scapy-code, or save the constructed packet in a pcap-file.


PREREQUISITES

Scapy, Python and the QT4 runtime must be installed on the machine 
for program to run. You can download the latest version of Scapy 
here: http://www.secdev.org/projects/scapy/

For all options is the packet "python-pyx" necessary.


In order to send IPv6 packets to the network directly from the GUI, 
you must have full privileges on the machine. Start the program with
<<<<<<< .mine
 $ sudo python gui.py
=======

  $ sudo gui.py

>>>>>>> .r37
or a similar command depending on your platform.



Copyright/License Notice
#########################################################################
# Copyright (c) 2011, Beuth Hochschule fuer Technik Berlin		        #
# 		scheffler[at]beuth-hochschule.de	                            #
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


