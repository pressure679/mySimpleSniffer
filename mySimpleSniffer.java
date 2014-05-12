// chapter 2.2-2.4
import org.jnetpcap.Pcap;

// chapter 2.6
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;

import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;

// chapter 2.7
import org.jnetpcap.packet.PcapPacketHandler;

// chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.JPacket;

import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.net.InetAddress;

public class mySimpleSniffer {

    public static void main(String args[]) throws Exception {

	// chapter 2.2-4
	// initiate packet capture device
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

	// enum networkinterfaces to get host address
	final String myinet = InetAddress.getLocalHost().getHostAddress();

	// initiate packet capture objects
	PcapHeader pcapheader = new PcapHeader();
	JBuffer jbuffer = new JBuffer(1512);
	final PcapPacket pcappacket = new PcapPacket(pcapheader, jbuffer);
	final Ip4 ip = new Ip4();

	// packet handler for packet capture
	PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {
	    // objects to get packet headers
	    StringBuffer myIps = new StringBuffer();
	    JBuffer jbuffer = pcappacket.getHeader(new Payload());
	    Ethernet eth = new Ethernet();
	    Icmp icmp = new Icmp();

	    public void nextPacket(PcapPacket pcappacket, String user) {

		// rest in function is about getting
		// headers & payload
		System.out.print("Dump:\n" + pcappacket.toHexdump());
		if (pcappacket.hasHeader(eth)) {
		    System.out.println("Ethernet:\t" + eth.typeEnum());
		}
		if (pcappacket.hasHeader(ip)) {
		    System.out.println(ip.source() + "\n" +
				       ip.destination() + "\n" +
				       myinet);
		    if (ip.source().toString() != myinet &&
			ip.destination().toString() != myinet) {
			System.out.println("IP:\t\t" + ip.typeEnum());

			// supposed to get ip route,
			// somewhat like traceroute
			/*
			if (pcappacket.hasHeader(icmp)) {
			    System.out.println("ICMP:\t\t" + icmp.typeEnum());
			} else {
			    System.out.println("No subheaders");
			}
			*/

			myIps.append(FormatUtils.ip(ip.source()) +
				     "\n" +
				     FormatUtils.ip(ip.destination()) +
				     "\n");
			System.out.println("\n\t*\t*\t*");
			System.out.println("src: " + FormatUtils.ip(ip.source()));
			System.out.println("dst: " + FormatUtils.ip(ip.destination()));
			System.out.println("\n\t*\t*\t*");
		    } else {
			System.out.println("src: " + FormatUtils.ip(ip.source()));
			System.out.println("dst: " + FormatUtils.ip(ip.destination()));
		    }
		} else {
		    System.out.println("No header");
		    System.out.println(pcappacket.getCaptureHeader());
		    return;
		}

		// Write files when you can get
		// ip route, meaningful hex dump payload,
		// and maybe decrypted data
		/*
		DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyy_HH:mm:ss");
		Date date = new Date();
		String myTime = dateFormat.format(date).toString();
		try {
		    File myFile = new File(myTime);
		    FileWriter fw = new FileWriter(myFile);
		    StringBuffer strbuff = new StringBuffer();
		    // doesn't write payload
		    fw.write(myIps.toString() +
			     strbuff.toString() +
			     "\n");
		    fw.close();
		} catch (IOException e) {
		    e.printStackTrace();
		}
		*/

		System.out.println();
	    }
	};
	pcap.loop(Integer.parseInt(args[0]), pcappackethandler, "pressure");
	pcap.close();
	System.out.println(myinet);
    }
}