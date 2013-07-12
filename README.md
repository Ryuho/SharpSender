SharpSender
===========

Commandline based packet sender written in C# using Pcap/SharpPcap/WinPcap.

Please install WinPcap 4.x to run this tool.

Download the binary by downloading this zip: https://raw.github.com/Ryuho/SharpSender/master/SharpSender.zip

    usage: SharpSender.exe -dip fe80::1:2:3 -icmpv6 -type 10 -code 10
           SharpSender.exe -dMAC FF:EE:CC:BB:AA:99 -ethertype 2049
           SharpSender.exe -dip 8.8.8.8 -udp -dport 9090 -sport 8888 -payload "hello world!"

        >SharpSender.exe -h
        usage: SharpSender.exe -icmp -dIP 127.0.0.1 -type 0 -code 0
        possible address args:
         -dIP <address>, -sIP <address>, -dMAC <address>, -sMAC <address>
        possible protocol args:
          -tcp, -udp, -icmp, -icmpv6, -ip <int>, -ethertype <int>
          -sPort <int>, -dPort <int>, -code <int>, -type <int>
        possible other args:
          -h, -adapter <adapter name>, -payload <string|hex>
        =========================
        Printing list of available adapters:
           VMware Network Adapter VMnet1
           VMware Network Adapter VMnet8
           Local Area Connection
