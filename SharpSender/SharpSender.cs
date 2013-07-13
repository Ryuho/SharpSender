using System;
using System.Collections.Generic;
using System.Text;

using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet.Utils;
using System.Diagnostics;

class Utility
{
    public static byte[] ParseHex(string hex)
    {
        int offset = hex.StartsWith("0x") ? 2 : 0;
        if ((hex.Length % 2) != 0)
        {
            throw new ArgumentException("Invalid length: " + hex.Length);
        }
        byte[] ret = new byte[(hex.Length - offset) / 2];

        for (int i = 0; i < ret.Length; i++)
        {
            ret[i] = (byte)((ParseNybble(hex[offset]) << 4)
                             | ParseNybble(hex[offset + 1]));
            offset += 2;
        }
        return ret;
    }

    private static int ParseNybble(char c)
    {
        switch (c)
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                return c - '0';
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                return c - 'A' + 10;
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
                return c - 'a' + 10;
        }
        throw new ArgumentException("Invalid hex digit: " + c);
    }

    private static List<string> GetListOfAdapters()
    {
        List<string> ret = new List<string>();
        CaptureDeviceList devices = CaptureDeviceList.Instance;
        foreach (ICaptureDevice dev in devices)
        {
            ret.Add(GetFriendlyName(dev));
        }
        return ret;
    }

    public static string GetFriendlyName(ICaptureDevice dev)
    {
        string ret = null;
        string toString = dev.ToString();
        string[] separators = { "\n" };
        string[] lines = toString.Split(separators, StringSplitOptions.RemoveEmptyEntries);
        foreach (string line in lines)
        {
            //Console.WriteLine(line);
            if(line.Contains("FriendlyName:"))
            {
                ret = line.Substring(13);
            }
        }
        return ret;
    }

    public static List<IPAddress> GetIPAddress(ICaptureDevice capDev)
    {
        //extract the device GUID
        string[] separators = { "{", "}" };
        string[] lines = capDev.Name.Split(separators, StringSplitOptions.RemoveEmptyEntries);
        string capDevGUID = lines[1];

        List<IPAddress> ret = new List<IPAddress>();
        foreach (SharpPcap.LibPcap.LibPcapLiveDevice dev in SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance)
        {
            if(dev.Name.Contains(capDevGUID))
            {
                for (int i = 0; i < dev.Addresses.Count; i++)
                {
                    var ip = dev.Addresses[i].Addr.ipAddress;
                    if (ip == null)
                        continue;

                    ret.Add(ip);
                }
            }
        }
        return ret;
    }

    public static void PrintHelp()
    {
        Console.WriteLine("usage: SharpSender.exe -icmp -dIP 127.0.0.1 -type 0 -code 0");
        Console.WriteLine("       SharpSender.exe -adapter 1 -dip fe80::1 -v6EH 60,44,6 -sport 9090 -dport 80");
        Console.WriteLine("       SharpSender.exe -adapter 1 -dip fe80::1 -v6EH 44,135,59");
        Console.WriteLine(@"       SharpSender.exe -adapter ""Ether"" -dMAC ee:ff:22:11:11:33 -ethertype 0xCAFE");
        Console.WriteLine("");
        Console.WriteLine("possible address args: ");
        Console.WriteLine(" -dIP <address>, -sIP <address>, -dMAC <address>, -sMAC <address>");
        Console.WriteLine("");
        Console.WriteLine("possible protocol args: ");
        Console.WriteLine("  -tcp, -udp, -icmp, -icmpv6, -ip <int>, -ethertype <int>");
        Console.WriteLine("  -sPort <int>, -dPort <int>, -code <int>, -type <int>");
        Console.WriteLine("  -v6EH <int,int,int...>");
        Console.WriteLine("");
        Console.WriteLine("possible other args: ");
        Console.WriteLine("  -h, -adapter <string|int>, -payload <string|hex>");
        Console.WriteLine("");
        Console.WriteLine("Printing list of available adapters:");
        int temp = 0;
        foreach (string line in GetListOfAdapters())
        {
            Console.WriteLine(temp + ":  " + line);
            temp++;
        }
    }

    public static ICaptureDevice PickDevice(Param param)
    {
        // Decide on a device to send packets on
        CaptureDeviceList devices = CaptureDeviceList.Instance;
        ICaptureDevice dev = null;

        //if adapter was picked by index number, pick that
        int pickedIndex = -1;
        bool isNumeric = int.TryParse(param.adapter, out pickedIndex);

        if (isNumeric)
        {
            IEnumerator<ICaptureDevice> capEnumerator = devices.GetEnumerator();
            int devIndex = 0;
            while (capEnumerator.MoveNext())
            {
                if (pickedIndex == devIndex)
                {
                    dev = capEnumerator.Current;
                    Console.WriteLine("Picked the adapter: " + GetFriendlyName(dev));
                    break;
                }
                devIndex++;
            }
        }
        else
        {
            foreach (ICaptureDevice curDev in devices)
            {
                bool adapterPicked = false;
                if (param.adapter == null)
                {
                    //these are the default adapter names that are commonly used
                    adapterPicked = Utility.GetFriendlyName(curDev).ToLower().Contains("Local Area Connection".ToLower());
                    adapterPicked |= Utility.GetFriendlyName(curDev).ToLower().Contains("Ethernet".ToLower());
                }
                else
                {
                    adapterPicked = Utility.GetFriendlyName(curDev).ToLower().Contains((param.adapter).ToLower());
                }

                if (dev == null && adapterPicked)
                {
                    dev = curDev;
                }
                else if (adapterPicked)
                {
                    dev = null;
                    break;
                }
            }
        }

        if (dev == null)
        {
            Console.WriteLine("Couldn't find one adapter to send packet on, sending it to all adapters.");
        }

        return dev;
    }
}

class Param
{
    //members
    public IPAddress dIP = null;// = IPAddress.Parse("8.8.8.8");
    public IPAddress sIP = null;// = IPAddress.Parse("255.255.255.255");
    public PhysicalAddress dMAC = null;// = PhysicalAddress.Parse("FF:FF:FF:FF:FF:FF");
    public PhysicalAddress sMAC = null;// = PhysicalAddress.Parse("FF:FF:FF:FF:FF:FF");
    public ushort dPort = 0;
    public ushort sPort = 0;
    public ushort code = 0;
    public ushort type = 0;
    public PacketType packetType = PacketType.ICMP;
    public IPProtocolType IPProtocol = IPProtocolType.IP;
    public EthernetPacketType EtherTypeProtocol = (EthernetPacketType)0x0800;
    public byte[] payload = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    public string adapter = null;
    public List<IPProtocolType> ExtentionHeader = new List<IPProtocolType>();

    //constructor, reads in the args
    public Param(string[] args)
    {
        for (int i = 0; i < args.Length;i++)
        {
            string curStr = args[i];

            try
            {
                if (String.Compare(curStr, "-adapter", true) == 0)
                {
                    string nextStr = args[++i];
                    adapter = nextStr;
                    Console.WriteLine("Read in adapter as: " + adapter);
                }
                else if (String.Compare(curStr, "-v6EH", true) == 0)
                {
                    string nextStr = args[++i];
                    string[] tempEHArray = nextStr.Split(',');
                    //ExtentionHeader = 
                        
                    int[] tempInt = Array.ConvertAll(tempEHArray, int.Parse);
                    foreach (int curInt in tempInt)
                    {
                        ExtentionHeader.Add((IPProtocolType)curInt);
                    }
                    packetType = PacketType.IP;
                    IPProtocol = IPProtocolType.IPV6;
                    
                    Console.WriteLine("Read in -v6EH as: " + string.Join(",", tempEHArray));
                    Console.WriteLine("Setting packetType as: " + packetType.ToString());
                    Console.WriteLine("Setting IPProtocol as: " + IPProtocol.ToString());
                }
                else if (String.Compare(curStr, "-dMAC", true) == 0)
                {
                    string nextStr = args[++i];
                    nextStr = nextStr.Replace(':', '-').ToUpper();
                    dMAC = PhysicalAddress.Parse(nextStr);
                    Console.WriteLine("Read in dMAC as: " + dMAC.ToString());
                }
                else if (String.Compare(curStr, "-sMAC", true) == 0)
                {
                    string nextStr = args[++i];
                    nextStr = nextStr.Replace(':', '-').ToUpper();
                    sMAC = PhysicalAddress.Parse(nextStr);
                    Console.WriteLine("Read in sMAC as: " + sMAC.ToString());
                }
                else if (String.Compare(curStr, "-dIP", true) == 0)
                {
                    string nextStr = args[++i];
                    dIP = IPAddress.Parse(nextStr);
                    Console.WriteLine("Read in dIP as: " + dIP.ToString());
                }
                else if (String.Compare(curStr, "-sIP", true) == 0)
                {
                    string nextStr = args[++i];
                    sIP = IPAddress.Parse(nextStr);
                    Console.WriteLine("Read in sIP as: " + sIP.ToString());
                }
                else if (String.Compare(curStr, "-IP", true) == 0)
                {
                    string nextStr = args[++i];
                    packetType = PacketType.IP;
                    if(nextStr.StartsWith("0x"))
                    {
                        IPProtocol = (IPProtocolType)Convert.ToInt32(nextStr, 16);
                    }
                    else
                    {
                        IPProtocol = (IPProtocolType)Convert.ToInt32(nextStr);
                    }
                    Console.WriteLine("Read in IP as: " + IPProtocol.ToString());
                }
                else if (String.Compare(curStr, "-EtherType", true) == 0)
                {
                    string nextStr = args[++i];
                    packetType = PacketType.EtherType;
                    if (nextStr.StartsWith("0x"))
                    {
                        EtherTypeProtocol = (EthernetPacketType)Convert.ToInt32(nextStr, 16);
                    }
                    else
                    {
                        EtherTypeProtocol = (EthernetPacketType)Convert.ToInt32(nextStr);
                    }
                    Console.WriteLine("Read in EtherType as: " + EtherTypeProtocol.ToString());
                }
                else if (String.Compare(curStr, "-sPort", true) == 0)
                {
                    string nextStr = args[++i];
                    sPort = (ushort)Int16.Parse(nextStr);
                    Console.WriteLine("Read in sPort as: " + sPort.ToString());
                }
                else if (String.Compare(curStr, "-dPort", true) == 0)
                {
                    string nextStr = args[++i];
                    dPort = (ushort)Int16.Parse(nextStr);
                    Console.WriteLine("Read in dPort as: " + dPort.ToString());
                }
                else if (String.Compare(curStr, "-type", true) == 0)
                {
                    string nextStr = args[++i];
                    type = (ushort)Int16.Parse(nextStr);
                    Console.WriteLine("Read in type as: " + type.ToString());
                }
                else if (String.Compare(curStr, "-code", true) == 0)
                {
                    string nextStr = args[++i];
                    code = (ushort)Int16.Parse(nextStr);
                    Console.WriteLine("Read in code as: " + code.ToString());
                }
                else if (String.Compare(curStr, "-payload", true) == 0)
                {
                    string nextStr = args[++i];
                    if (nextStr.StartsWith("0x"))
                    {
                        payload = Utility.ParseHex(nextStr);
                        Console.WriteLine("Read in -payload as: 0x" + BitConverter.ToString(payload));
                    }
                    else
                    {
                        payload = Encoding.ASCII.GetBytes(nextStr);
                        Console.WriteLine("Read in -payload as: " + System.Text.Encoding.Default.GetString(payload));
                    }

                    
                }
                else if (String.Compare(curStr, "-adapter", true) == 0)
                {
                    string nextStr = args[++i];
                    adapter = nextStr;
                    Console.WriteLine("Read in -adapter as: " + adapter);
                }
                else if (String.Compare(curStr, "-ICMP", true) == 0)
                {
                    packetType = PacketType.ICMP;
                }
                else if (String.Compare(curStr, "-tcp", true) == 0)
                {
                    packetType = PacketType.TCP;
                }
                else if (String.Compare(curStr, "-udp", true) == 0)
                {
                    packetType = PacketType.UDP;
                }
                else if (String.Compare(curStr, "-ICMPv6", true) == 0)
                {
                    packetType = PacketType.ICMPv6;
                }
                else if (String.Compare(curStr, "-h", true) == 0)
                {
                    Utility.PrintHelp();
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("Unrecognized param: " + curStr);
                    Utility.PrintHelp();
                    Environment.Exit(0);
                }
            }
            catch (IndexOutOfRangeException)
            {
                Console.WriteLine("Another arg was expected after " + curStr);
                Environment.Exit(1);
            }
            catch (FormatException)
            {
                Console.WriteLine("The address specified for " + curStr + " was not in the correct format.");
                Environment.Exit(1);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception caught while handling commandline.");
                Console.WriteLine("Last arg handled:" + curStr);
                Console.WriteLine("Actual exception: " + e.ToString());
                Environment.Exit(1);
            }
        }

        // do some checks to make sure this param combination is valid

        if (dIP == null && dMAC == null)
        {
            Console.WriteLine("-dIP or -dMAC has to be set to send a packet.");
            Environment.Exit(1);
        }

        if (dIP == null &&
            (packetType == PacketType.ICMP ||
            packetType == PacketType.ICMPv6 ||
            packetType == PacketType.IP ||
            packetType == PacketType.TCP ||
            packetType == PacketType.UDP))
        {
            Console.WriteLine("dIP needs to be defined for IP based packets.");
            Environment.Exit(1);
        }

        if (packetType == PacketType.ICMPv6 && (dIP == null || !dIP.ToString().Contains(":")))
        {
            Console.WriteLine("dIP needs to be IPv6 for ICMPv6 packets.");
            Environment.Exit(1);
        }

        if (ExtentionHeader.Count != 0 && (dIP == null || !dIP.ToString().Contains(":")))
        {
            Console.WriteLine("dIP needs to be IPv6 for ExtensionHeader packets.");
            Environment.Exit(1);
        }

        if (ExtentionHeader.Count == 1 )
        {
            Console.WriteLine("There needs to be at least 2 extension headers.");
            Environment.Exit(1);
        }

        if (dMAC == null && packetType == PacketType.EtherType)
        {
            Console.WriteLine("dMAC needs to be defined for EtherType based packets.");
            Environment.Exit(1);
        }
    }
    
    public void UpdateDevInfo(ICaptureDevice dev)
    {
        // if we are sending packet to all adapters
        if (dev == null)
        {
            if (sIP == null)
            {
                sIP = IPAddress.Parse("255.255.255.255");
                Console.WriteLine("Set sIP to: " + sIP.ToString());
            }
            if (dIP == null)
            {
                dIP = IPAddress.Parse("255.255.255.255");
                Console.WriteLine("Set dIP to: " + dIP.ToString());
            }
            if (sMAC == null)
            {
                sMAC = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");
                Console.WriteLine("Set sMAC to: " + sMAC.ToString());
            }
            if (dMAC == null)
            {
                dMAC = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");
                Console.WriteLine("Set dMAC to: " + dMAC.ToString());
            }
        }
        // if we picked an actual adapter
        else
        {
            dev.Open();
            // if source address is not defined, fill out the sIP
            List<IPAddress> ipAddresses = Utility.GetIPAddress(dev);
            foreach (IPAddress add in ipAddresses)
            {
                if (sIP == null && dIP != null)
                {
                    if (dIP.ToString().Contains(".") && add.ToString().Contains("."))
                    {
                        sIP = add;
                        Console.WriteLine("Set sIP to: " + add.ToString());
                    }
                    else if (dIP.ToString().Contains(":") && add.ToString().Contains(":"))
                    {
                        sIP = add;
                        Console.WriteLine("Set sIP to: " + add.ToString());
                    }
                }
            }

            if(sIP == null)
            {
                Console.WriteLine("The chosen adapter did not have a valid address");
                Environment.Exit(1);
            }

            //fill out source mac if it is null
            if (sMAC == null)
            {
                sMAC = dev.MacAddress;
                Console.WriteLine("Set sMAC to: " + sMAC.ToString());
            }
            if (dMAC == null)
            {
                dMAC = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");
                Console.WriteLine("Set dMAC to: " + dMAC.ToString());
            }
            dev.Close();
        }
    }

    public enum PacketType
    {
        TCP,
        UDP,
        ICMP,
        ICMPv6,
        IP,
        EtherType,
        Other
    }
}

class PacketFactory
{
    static public Packet CreatePacket(Param param)
    {
        Packet ret = null;

        //create layer 4
        if(param.packetType == Param.PacketType.TCP)
        {
            TcpPacket tcpPacket = new TcpPacket(param.sPort, param.dPort);
            if (param.dIP.ToString().Contains("."))
            {
                IPv4Packet ipPacket = new IPv4Packet(param.sIP, param.dIP);
                ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV4);
                ipPacket.PayloadPacket = tcpPacket;
                tcpPacket.PayloadData = param.payload;
                ret.PayloadPacket = ipPacket;
                ipPacket.UpdateCalculatedValues();
                ipPacket.UpdateIPChecksum();
                tcpPacket.Checksum = (ushort)tcpPacket.CalculateTCPChecksum();
            }
            else
            {
                IPv6Packet ipPacket = new IPv6Packet(param.sIP, param.dIP);
                ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV6);
                ipPacket.PayloadPacket = tcpPacket;
                tcpPacket.PayloadData = param.payload;
                ret.PayloadPacket = ipPacket;
            }

        }
        else if (param.packetType == Param.PacketType.UDP)
        {
            UdpPacket udpPacket = new UdpPacket(param.sPort, param.dPort);
            if (param.dIP.ToString().Contains("."))
            {
                IPv4Packet ipPacket = new IPv4Packet(param.sIP, param.dIP);
                ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV4);
                ipPacket.PayloadPacket = udpPacket;
                udpPacket.PayloadData = param.payload;
                udpPacket.UpdateUDPChecksum();
                ipPacket.PayloadLength = (ushort)(ipPacket.PayloadLength + param.payload.Length);
                ipPacket.UpdateIPChecksum();
                ret.PayloadPacket = ipPacket;
            }
            else
            {
                IPv6Packet ipPacket = new IPv6Packet(param.sIP, param.dIP);
                ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV6);
                ipPacket.PayloadPacket = udpPacket;
                udpPacket.PayloadData = param.payload;
                udpPacket.UpdateUDPChecksum();
                ipPacket.PayloadLength = (ushort)(ipPacket.PayloadLength + param.payload.Length);
                ret.PayloadPacket = ipPacket;
            }
        }
        else if(param.packetType == Param.PacketType.ICMP)
        {
            ICMPv4Packet icmpPacket = new ICMPv4Packet(new ByteArraySegment(new byte[32]));
            if (param.type != 0 && param.code != 0)
            {
                icmpPacket.TypeCode = (ICMPv4TypeCodes)((param.type * 256) + (param.code));
            }
            else if (param.type != 0)
            {
                icmpPacket.TypeCode = (ICMPv4TypeCodes)((param.type * 256));
            }
            else
            {
                icmpPacket.TypeCode = ICMPv4TypeCodes.EchoRequest;
            }

            IPv4Packet ipPacket = new IPv4Packet(param.sIP, param.dIP);
            ipPacket.PayloadPacket = icmpPacket;
            ipPacket.Checksum = ipPacket.CalculateIPChecksum();
            ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV4);
            ret.PayloadPacket = ipPacket;
        }
        else if (param.packetType == Param.PacketType.ICMPv6)
        {
            ICMPv6Packet icmpv6Packet = new ICMPv6Packet(new ByteArraySegment(new byte[32]));
            if (param.type != 0)
            {
                icmpv6Packet.Type = (ICMPv6Types)(param.type);
            }
            else
            {
                icmpv6Packet.Type = ICMPv6Types.EchoRequest;
            }

            if (param.code != 0)
            {
                icmpv6Packet.Code = (byte)param.code;
            }
            else
            {
                icmpv6Packet.Code = (byte)0;
            }
            IPv6Packet ipPacket = new IPv6Packet(param.sIP, param.dIP);
            ipPacket.PayloadPacket = icmpv6Packet;
            ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV6);
            ret.PayloadPacket = ipPacket;
        }
        else if (param.packetType == Param.PacketType.IP)
        {
            if (param.dIP.ToString().Contains("."))
            {
                ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV4);
                IPv4Packet ipPacket = new IPv4Packet(param.sIP, param.dIP);
                ipPacket.Protocol = param.IPProtocol;
                ipPacket.PayloadData = param.payload;
                ipPacket.UpdateCalculatedValues();
                ret.PayloadPacket = ipPacket;
                ipPacket.UpdateIPChecksum();
            }
            else
            {
                ret = new EthernetPacket(param.sMAC, param.dMAC, EthernetPacketType.IpV6);

                //if extension headers were not specified, just put the payload
                if (param.ExtentionHeader.Count == 0)
                {
                    IPv6Packet ipPacket = new IPv6Packet(param.sIP, param.dIP);
                    ipPacket.Protocol = param.IPProtocol;
                    ipPacket.PayloadData = param.payload;
                    ipPacket.PayloadLength = (ushort)param.payload.Length;
                    ipPacket.UpdateCalculatedValues();
                    ret.PayloadPacket = ipPacket;
                }
                else
                {
                    ret = PacketFactory.CreateEHPacket(param, (EthernetPacket)ret);
                }
                ret.UpdateCalculatedValues();
            }
        }
        else if(param.packetType == Param.PacketType.EtherType)
        {
            ret = new EthernetPacket(param.sMAC, param.dMAC, param.EtherTypeProtocol);
            byte[] etherBuffer = (new byte[64]);
            var payload = new byte[etherBuffer.Length + (param.payload).Length];
            etherBuffer.CopyTo(payload, 0);
            (param.payload).CopyTo(payload, etherBuffer.Length);
            ret.PayloadData = payload;
            ret.UpdateCalculatedValues();
        }

        return ret;
    }

    //terrible hack to get extension headers working
    private static EthernetPacket CreateEHPacket(Param param, EthernetPacket ret)
    {
        IPv6Packet ipPacket = new IPv6Packet(param.sIP, param.dIP);
        ipPacket.Protocol = (IPProtocolType)param.ExtentionHeader[0];
        param.ExtentionHeader.RemoveAt(0);

        //need to find out what is the last packet so that we can decide on the length of the packet
        IPProtocolType endEH = param.ExtentionHeader[param.ExtentionHeader.Count - 1];
        int lastHeaderLength = 0;
        switch (endEH)
        {
            case IPProtocolType.TCP:
                lastHeaderLength = 20;
                break;
            case IPProtocolType.UDP:
                lastHeaderLength = 8;
                break;
            case IPProtocolType.ICMP:
                lastHeaderLength = 8;
                break;
            default:
                lastHeaderLength = 64;
                break;
        }

        //calculate the Extension header size
        int EHSize = 0;
        foreach(IPProtocolType eh in param.ExtentionHeader)
        {
            if(eh == IPProtocolType.FRAGMENT)
            {
                EHSize += 8;
            }
            else
            {
                EHSize += 24;
            }
        }

        if (ipPacket.Protocol == IPProtocolType.FRAGMENT)
        {
            EHSize -= 16;
        }

        byte[] tempPayload = new byte[EHSize + param.payload.Length + lastHeaderLength];
        param.payload.CopyTo(tempPayload, EHSize + lastHeaderLength);

        int loc = 0;
        byte previous = (byte)ipPacket.Protocol;
        foreach (byte eh in param.ExtentionHeader)
        {
            tempPayload.SetValue((byte)eh, loc);
            tempPayload.SetValue((byte)2, loc + 1);
            if ((IPProtocolType)previous == IPProtocolType.FRAGMENT)
            {
                loc += 8;
            }
            else
            {
                loc += 24;
            }
            previous = eh;
        }

        //set the port if the last EH is tcp or udp
        if (endEH == IPProtocolType.TCP || endEH == IPProtocolType.UDP)
        {
            //set the port numbers
            tempPayload.SetValue((byte)(param.sPort >> 8), loc);
            tempPayload.SetValue((byte)param.sPort, loc + 1);
            tempPayload.SetValue((byte)(param.dPort >> 8), loc + 2);
            tempPayload.SetValue((byte)param.dPort, loc + 3);
        }
        if (endEH == IPProtocolType.TCP)
        {
            tempPayload.SetValue((byte)0x50, loc + 12);
        }
        else if (endEH == IPProtocolType.UDP)
        {
            //set the length of the payload
            Int16 length = (Int16)(lastHeaderLength + param.payload.Length);
            BitConverter.GetBytes(length).CopyTo(tempPayload, loc + 5);
            tempPayload.SetValue((byte)0x12, loc + 6);
            tempPayload.SetValue((byte)0x34, loc + 7);
        }

        ipPacket.PayloadData = tempPayload;
        ipPacket.PayloadLength = (ushort)tempPayload.Length;
        ipPacket.UpdateCalculatedValues();
        ret.PayloadPacket = ipPacket;
        return ret;
    }
}

namespace SharpSender
{
    class SharpSender
    {
        static void Main(string[] args)
        {
            try
            {
                //parse args, and put them into the Param object
                Param param = new Param(args);

                //pick the right adapter depending on the arg, null is returned if it couldn't decide
                ICaptureDevice dev = Utility.PickDevice(param);

                //update the source mac and ip addresses depending on the device that was picked
                //default values are placed if device was null
                param.UpdateDevInfo(dev);

                //actually create the packet
                Packet packet = PacketFactory.CreatePacket(param);

                Console.WriteLine("Sending the following packet:");
                Console.WriteLine(packet.ToString());
                byte[] packetBytes = packet.Bytes;

                //if no specific adapter was picked, send to every adapters, else just send it to that adapter
                if(dev == null)
                {
                    foreach (ICaptureDevice tempDev in CaptureDeviceList.Instance)
                    {
                        Console.WriteLine("-- Seending Packet to: " + Utility.GetFriendlyName(tempDev));
                        tempDev.Open();
                        tempDev.SendPacket(packetBytes);
                        Console.WriteLine("-- Packet sent successfuly.");
                        tempDev.Close();
                    }
                }
                else
                {
                    Console.WriteLine("-- Seending Packet to: " + Utility.GetFriendlyName(dev));
                    dev.Open();
                    // Send the packet out the network device
                    dev.SendPacket(packetBytes);
                    Console.WriteLine("-- Packet sent successfuly.");
                    dev.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("-- " + e.Message);
                Console.WriteLine("-- " + e.StackTrace);
            }
        }
    }
}
