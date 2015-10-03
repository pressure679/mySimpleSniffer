//    This software is for intended for simple network auditing.
//    Copyright (C) 2014 Vittus Peter Ove Maqe Mikiassen
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program. If not, see <http://www.gnu.org/licenses/>.

// I highly used http://jnetpcap.com/?q=examples and http://jnetpcap.com/?q=tutorial to make this

import org.jnetpcap.Pcap;

// chapter 2.6
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;

// to format data and get headers
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Rip;
// import org.jnetpcap.protocol.voip;
// import org.jnetpcap.protocol.vpn;
// import org.jnetpcap.protocol.wan;
import org.jnetpcap.packet.JRegistry;

// chapter 2.7
import org.jnetpcap.packet.PcapPacketHandler;

// chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.JPacket;

// For writing package data to file
import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

// For getting host IP address & MAC
import java.net.InetAddress;
import java.util.Enumeration;
import java.net.NetworkInterface;

// For formatting mac & ip output
import org.jnetpcap.packet.format.FormatUtils;

// General Utils
// import java.util.List;
// import java.util.ArrayList;
import java.util.Arrays;

public class sniffer {

	public static Ip4 ip = new Ip4();
	public static Ethernet eth = new Ethernet();
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
	/*	public static Rip rip = new Rip() {
			void printheader() {
			System.out.println(rip.getHeader());
			}
			}; */
	
	public static Arp arp = new Arp();
	public static Payload payload = new Payload();
	public static byte[] payloadContent;
	public static boolean readdata = false;	public static byte[] myinet = new byte[3];
	public static byte[] mymac = new byte[5];

	public static InetAddress inet;
	public static Enumeration e;
	public static NetworkInterface n;
	public static Enumeration ee;

  public static void main(String args[]) throws Exception {
    // chapter 2.2-4
    // initiate packet capture device
    final int snaplen = Pcap.DEFAULT_SNAPLEN;
    final int flags = Pcap.MODE_PROMISCUOUS;
    final int timeout = Pcap.DEFAULT_TIMEOUT;
    final StringBuilder errbuf = new StringBuilder();
    Pcap pcap = Pcap.openLive(args[0], snaplen, flags, timeout, errbuf);
    if (pcap == null) {
      System.out.println("Error while opening device for capture: " + errbuf.toString());  
      return;
    }

		// Get local address
		e = NetworkInterface.getNetworkInterfaces();
		while (e.hasMoreElements()) {
			n = (NetworkInterface)e.nextElement();
			if (args[0].equals(n.getDisplayName())) {
				ee = n.getInetAddresses();
				mymac = n.getHardwareAddress();
				while (ee.hasMoreElements()) {
					inet = (InetAddress)ee.nextElement();
					System.out.println(n.getDisplayName() + " " + inet);
				}
			}
		}
		// Get IPv4 manually instead of looping through all IP's
		// myinet = inet.getAddress();

		// packet handler for packet capture
		pcap.loop(Integer.parseInt(args[1]), pcappackethandler, "pressure");
		pcap.close();
	}

	public static PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {
		public void nextPacket(PcapPacket pcappacket, String user) {
			if (pcappacket.hasHeader(ip)) {
				if (FormatUtils.ip(ip.source()) != FormatUtils.ip(myinet) &&
						FormatUtils.ip(ip.destination()) != FormatUtils.ip(myinet)) {
					System.out.println();
					System.out.println("IP type:\t" + ip.typeEnum());
					System.out.println("IP src:\t-\t" + FormatUtils.ip(ip.source()));
					System.out.println("IP dst:\t-\t" + FormatUtils.ip(ip.destination()));
					readdata = true;
				}
			}
			if (pcappacket.hasHeader(eth) &&
					readdata == true) {
				System.out.println("Ethernet type:\t" + eth.typeEnum());
				System.out.println("Ethernet src:\t" + FormatUtils.mac(eth.source()));
				System.out.println("Ethernet dst:\t" + FormatUtils.mac(eth.destination()));
			}
			if (pcappacket.hasHeader(tcp) &&
					readdata == true) {
				System.out.println("TCP src port:\t" + tcp.source());
				System.out.println("TCP dst port:\t" + tcp.destination());
			} else if (pcappacket.hasHeader(udp) &&
								 readdata == true) {
				System.out.println("UDP src port:\t" + udp.source());
				System.out.println("UDP dst port:\t" + udp.destination());
			}
			/*			if (pcappacket.hasHeader(rip) &&
							readdata == true) {
							System.out.println("RIP count:\t" + rip.count());
							System.out.println("RIP header:\t" + rip.getHeader());
							} */
			if (pcappacket.hasHeader(arp) &&
					readdata == true) {
							
				// System.out.println("ARP decode header:\t" + arp.decodeHeader());
				// System.out.println("ARP hardware type:\t" + arp. hardwareType());
				// System.out.println("ARP hw type descr:\t" + arp.hardwareTypeDescription());
				// System.out.println("ARP hw type enum:\t" + arp.hardwareTypeEnum());
				// System.out.println("ARP hlen:\t-\t" + arp.hlen());
				// System.out.println("ARP operation:\t-\t" + arp.operation());
				// System.out.println("ARP plen:\t-\t" + arp.plen());
				// System.out.println("ARP protocol type:\t" + arp.protocolType());
				// System.out.println("ARP prtcl type descr:\t" + arp.protocolTypeDescription());
				// System.out.println("ARP prtcl type enum:\t" + arp.protocolTypeEnum());
				// System.out.println("ARP sha:\t-\t" + FormatUtils.mac(arp.sha()));
				// System.out.println("ARP sha length:\t-\t" + arp.shaLength());
				// System.out.println("ARP spa:\t-\t" + FormatUtils.ip(arp.spa()));
				// System.out.println("ARP spa length:\t-\t" + arp.spaLength());
				// System.out.println("ARP spa offset:\t-\t" + arp.spaOffset());
				// System.out.println("ARP tha:\t-\t" + FormatUtils.mac(arp.tha()));
				// System.out.println("ARP tha length:\t-\t" + arp.thaLength());
				// System.out.println("ARP tha offset:\t-\t" + arp.thaOffset());
				// System.out.println("ARP tpa:\t-\t" + FormatUtils.ip(arp.tpa()));
				// System.out.println("ARP tpa length:\t-\t" + arp.tpaLength());
				// System.out.println("ARP tpa offset:\t-\t" + arp.tpaOffset());
				System.out.println("ARP Packet!");
				readdata = true;
			}
			if (pcappacket.hasHeader(payload) && 
					readdata == true) {
				payloadContent = payload.getPayload();
				System.out.println("Payload:\n");
				for (int x = 0; x < payloadContent.length; x++) {
					System.out.print(payload.toHexdump());
				}
			}
			if (readdata == true) System.out.println("-\t-\t-\t-\t-");
			readdata = false;
		}
	};
	// public static void writeDump(
}
