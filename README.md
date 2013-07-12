SharpSender
===========

Commandline based packet sender written in C# using Pcap/SharpPcap/WinPcap.
Please install WinPcap 4.x to run this tool.

Please download the binary file by downloading "git:SharpSender/SharpSender.zip".

usage: SharpSender.exe -icmpv6 fe80::1:2:3 -type 10 -code 10
       SharpSender.exe -dMAC FF:EE:CC:BB:AA:99 -ethertype 2049
       SharpSender.exe -dip 8.8.8.8 -udp -dport 9090 -sport 8888 -payload "hello world!"