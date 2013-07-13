SharpSender
===========

Commandline based packet sender written in C# using Pcap/SharpPcap/WinPcap.

This tool requires the following: 
 - WinPcap 4.x
 - .NET Framework 3.5

This tool is tested to work with Windows XP up to Windows 8.
 
Download the binary by downloading this zip: https://raw.github.com/Ryuho/SharpSender/master/SharpSender.exe

        SharpSender.exe -h
        usage: SharpSender.exe -icmp -dIP 127.0.0.1 -type 0 -code 0
               SharpSender.exe -adapter 1 -dip fe80::1 -v6EH 0,43,17
               SharpSender.exe -adapter "Ether" -dMAC ee:ff:22:11:11:33 -ethertype 0xCAFE

        possible address args:
         -dIP <address>, -sIP <address>, -dMAC <address>, -sMAC <address>

        possible protocol args:
          -tcp, -udp, -icmp, -icmpv6, -ip <int>, -ethertype <int>
          -sPort <int>, -dPort <int>, -code <int>, -type <int>
          -v6EH <int,int,int...>

        possible other args:
          -h, -adapter <string|int>, -payload <string|hex>

        Printing list of available adapters:
        0:   Local Area Connection 2
        1:   Wireless Network Connection
        2:   Local Area Connection 3
        3:   Bluetooth Network Connection
        4:   Local Area Connection

===========
To build this from source, you need the following installed:
 - VS2010 or VS2012
 - 7zip
 - ILMerge