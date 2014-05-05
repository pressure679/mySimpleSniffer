// chapter 2.2-2.4
import org.jnetpcap.Pcap;

// chapter 2.5
import org.jnetpcap.PcapBpfProgram;

// chapter 2.6
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import java.nio.ByteBuffer;
import org.jnetpcap.packet.PcapPacket;

// chapter 2.7
// only has nextPacket(*Handler) method
import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacketHandler;

// chapter 2.8
import org.jnetpcap.PcapDumper;
import java.io.File;

// chapter 2.9
// injection is only supported in Windows 32-bit platforms

// chapter 3.1.1
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

// chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.JPacket;

// chapter 3.2
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.JRegistry;

// chapter 3.4
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.format.XmlFormatter;
import java.io.IOException;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.util.PcapPacketArrayList;

// for formatting Ip4.getSource()
import org.jnetpcap.packet.format.FormatUtils;
import java.util.Arrays;

// for dumping packets
import org.jnetpcap.PcapDumper;
import java.io.File;

import java.net.InetAddress;
import java.util.List;
import java.util.ArrayList;

public class mySimpleSniffer {

    public static void main(String args[]) throws Exception {

	// chapter 2.2-4
	int snaplen = Pcap.DEFAULT_SNAPLEN;
	int flags = Pcap.MODE_PROMISCUOUS;
	int timeout = Pcap.DEFAULT_TIMEOUT;
	StringBuilder errbuf = new StringBuilder();
	Pcap pcap = Pcap.openLive("wlan0", snaplen, flags, timeout, errbuf);
	if (pcap == null) {
	    System.err.printf("Error while opening device for capture: "  
			      + errbuf.toString());  
	    return;
	}

	/*
	// chapter 2.5
	// keeps returning error on compiling pcap

	// subnetmask for chapter 2.5
	int netmask = 0xFFFFFF00; // 255.255.255.0

	InetAddress inet = InetAddress.getLocalHost();
	String expression = inet.getHostAddress();
	PcapBpfProgram program = new PcapBpfProgram();
	int optimize = 0;
	if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
	    System.out.println("Error compiling pcap");
	    System.out.println(expression);
	    System.err.println(pcap.getErr());
	    return;
	}
	if (pcap.setFilter(program) != Pcap.OK) {
	    System.out.println("Error setting cilter on pcap");
	    System.err.println(pcap.getErr());
	    return;
	}
	*/

	// chapter 2.6-7
	PcapHeader pcapheader = new PcapHeader();
	JBuffer jbuffer = new JBuffer(1512);
	/*
	 cant be instantiated
	 ByteBuffer bbuffer = new ByteBuffer();
	*/
	PcapPacket pcappacket = new PcapPacket(pcapheader, jbuffer);
	final PcapPacketArrayList pparr = new PcapPacketArrayList();
	final InetAddress lchost = InetAddress.getLocalHost();
	final Ip4 ip = new Ip4();
	JPacket jpacket = (JPacket)pcappacket;
	JHeader jheader = null;
	final byte[] mynet = {(byte)192, (byte)168, (byte)0, (byte)100};

	// classic example
	PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {
	    StringBuffer myIps = new StringBuffer();
	    public void nextPacket(PcapPacket pcappacket, String user) {
		/*
		  int end = pcappacket.getTotalSize();
		  System.out.println(pcappacket.getUTF8String(0, end));
		*/

		// chapter 3.1.1
		/*
		  Tcp tcp = new Tcp();
		  Udp udp = new Udp();
		  if (pcappacket.hasHeader(tcp)) {
		  System.out.print("pcappacket tcp destination: ");
		  System.out.println(tcp.destination());
		  } else if (pcappacket.hasHeader(udp)) {
		  System.out.print("pcappacket udp destination: ");
		  System.out.println(udp.destination());
		  }
		*/

		// for stringing byte arrays of ip addresses

		// chapter 3.1.2
		if (pcappacket.hasHeader(ip)) {
		    if (ip.source()[3] != mynet[3] &&
			ip.destination()[3] != mynet[3]) {
			myIps.append(FormatUtils.ip(ip.source()));
			System.out.println("\n\t*\t*\t*\n");
			System.out.println("src: " + FormatUtils.ip(ip.source()));
			System.out.println("dst: " + FormatUtils.ip(ip.destination()));
			System.out.println("\n\t*\t*\t*\n");
		    } else {
			System.out.println("src: " + FormatUtils.ip(ip.source()));
			System.out.println("dst: " + FormatUtils.ip(ip.destination()));
		    }
		} else {
		    return;
		}

		/*
		  Ip4.Timestamp ts = new Ip4.Timestamp();
		  Ip4.LooseSourceRoute lsroute = new Ip4.LooseSourceRoute();
		  Ip4.StrictSourceRoute ssroute = new Ip4.StrictSourceRoute();
		  if (jpacket.hasHeader(ip) && ip.hasSubHeaders()) {
		  if (ip.hasSubHeader(lsroute)) {
		  System.out.println("Has loose route");
		  }
		  if (ip.hasSubHeader(ssroute)) {
		  System.out.println("Has strict route");
		  }
		  if (ip.hasSubHeader(ts)) {
		  System.out.println("Has timestamp");
		  }
		  System.out.println(jpacket.getState());
		  }
		*/

		// chapter 3.4
		/*
		  try {
		  TextFormatter txtout = new TextFormatter(System.out);
		  txtout.format(jpacket);
		  } catch (IOException e) {
		  e.printStackTrace();
		  }
		*/
		System.out.println();
	    }
	};
	pcap.loop(Integer.parseInt(args[0]), pcappackethandler, "Pressure");
	pcap.close();
    }
}
