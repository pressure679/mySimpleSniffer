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
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
// import org.jnetpcap.protocol.voip;
// import org.jnetpcap.protocol.vpn;
// import org.jnetpcap.protocol.wan;

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

import java.net.InetAddress;
import java.util.Enumeration;
import java.net.NetworkInterface;

import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.PcapIf;

// import java.util.List;
// import java.util.ArrayList;
import java.util.Arrays;

public class mySimpleSniffer {
  public static void main(String args[]) throws Exception {
    // chapter 2.2-4
    // initiate packet capture device
    int snaplen = Pcap.DEFAULT_SNAPLEN;
    int flags = Pcap.MODE_PROMISCUOUS;
    int timeout = Pcap.DEFAULT_TIMEOUT;
    StringBuilder errbuf = new StringBuilder();
    Pcap pcap = Pcap.openLive(args[0], snaplen, flags, timeout, errbuf);
    if (pcap == null) {
      System.err.printf("Error while opening device for capture: " 
																								+ errbuf.toString());  
      return;
    }
    // Get local address
    InetAddress[] inets = new InetAddress[10];
    Enumeration e = NetworkInterface.getNetworkInterfaces();
    int counter = 0;
				byte[] mymacget = {(byte)52, (byte)35, (byte)141, (byte)33, (byte)30, (byte)67};
    while (e.hasMoreElements()) {
      NetworkInterface n = (NetworkInterface) e.nextElement();
      Enumeration ee = n.getInetAddresses();
						if (counter == 1) mymacget = n.getHardwareAddress();
      while (ee.hasMoreElements()) {
								inets[counter] = (InetAddress) ee.nextElement();
								counter++;
      }
    }
				final byte[] myinet = inets[1].getAddress();
				final byte[] mymac = mymacget;

    final Ip4 ip = new Ip4();
				final Ethernet eth = new Ethernet();
				final Tcp tcp = new Tcp();
				final Udp udp = new Udp();
				final Arp arp = new Arp();
				final Icmp icmp = new Icmp();
				final Payload payload = new Payload();

    // packet handler for packet capture
    PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {

						byte[] payloadContent;
						boolean readdata = false;

      public void nextPacket(PcapPacket pcappacket, String user) {

								if (pcappacket.hasHeader(ip)) {
										if (ip.source()[3] != myinet[3] &&
														ip.destination()[3] != myinet[3]) {
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
										System.out.println("TCP port:\t" + tcp.destination());
								} else if (pcappacket.hasHeader(udp) &&
																			readdata == true) {
										System.out.println("UDP port:\t" + udp.destination());
								}
								if (pcappacket.hasHeader(payload) && 
												readdata == true) {
										payloadContent = payload.getPayload();
										System.out.println("Payload:\n");
										for (int x = 0; x < payloadContent.length; x++) {
												System.out.print("%02X" + payloadContent[x] + " ");
										}
								}
								if (readdata)	System.out.println("-\t-\t-\t-\t-");
								readdata = false;
						}
				};
				pcap.loop(Integer.parseInt(args[1]), pcappackethandler, "pressure");
				pcap.close();
		}
}
