# scapy-gui-ipv6 

A GUI for IPv6 Packetgeneration with Scapy

## Description

This tool provides a GUI for the Python network tool Scapy.

It serves as a learning tool for packet generation with Python and as a tool for rapid IPv6 packet generation.

## Installation

You can simply download the current version from here: 

http://hcode.google.com/p/scapy-gui-ipv6/downloads/list

Unzip and run the included Python 'gui.py' script as root or using 'sudo'. Extended privileges are only required if the GUI is used to actually send packets to the network. It can be run by any non-priviledged users in order to build Scapy-code, or save the constructed packet in a pcap-file.

## Prerequisites

Scapy, Python2 and the QT4 runtime must be installed on the machine for program to run. You can download the latest version of Scapy here: 

http://www.secdev.org/projects/scapy/

For all options is the packet "python-pyx" necessary.

In order to send IPv6 packets to the network directly from the GUI, you must have full privileges on the machine. Start the program with

    $ sudo python2 gui.py

or a similar command depending on your platform.
