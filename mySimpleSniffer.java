// chapter 2.2-2.4
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

	/* Java simply won't get host address..
	// enum networkinterfaces to get host address
	int x = 0;
	InetAddress[] lc = new InetAddress[3];
	NetworkInterface neti = NetworkInterface.getByName("wlan0");
	Enumeration e = neti.getInetAddresses();
	while(e.hasMoreElements()) {
	    NetworkInterface n = (NetworkInterface) e.nextElement();
	    Enumeration ee = n.getInetAddresses();
	    while (ee.hasMoreElements()) {
		lc[x] = (InetAddress) ee.nextElement();
		x++;
	    }
	}
	final String myinet = InetAddress.getLocalHost().getHostAddress();
	*/
	final byte[] myinet = {(byte)192, (byte)168, (byte)0, (byte)100};

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
	    byte[] sip = new byte[3];
	    byte[] dip = new byte[3];

	    public void nextPacket(PcapPacket pcappacket, String user) {

		// rest in function is about getting
		// headers & payload
		System.out.print("Dump:\n" + pcappacket.toHexdump());
		if (pcappacket.hasHeader(eth)) {
		    System.out.println("Ethernet:\t" + eth.typeEnum());
		}
		if (pcappacket.hasHeader(ip)) {

		    // myinet is not set to host address
		    // but loopback address
		    if (ip.source() != myinet &&
			ip.destination() != myinet) {
			System.out.println("IP:\t\t" + ip.typeEnum());
			sip = ip.source();
			dip = ip.destination();
			System.out.print("src:\t-\t");
			for (int x = 0; x < 4; x++) {
			    if (sip[x] < 0) {
				System.out.print(256 + sip[x]);
				if (x < 3) {
				    System.out.print(".");
				}
			    } else {
				System.out.print(256 - sip[x]);
				if (x < 3) {
				    System.out.print(".");
				}
			    }
			}
			System.out.println();
			System.out.print("dst:\t\t");
			for (int x = 0; x < 4; x++) {
			    if (dip[x] < 0) {
				System.out.print(256 + dip[x]);
				if (x < 3) {
				    System.out.print(".");
				}
			    } else {
				System.out.print(256 - dip[x]);
				if (x < 3) {
				    System.out.print(".");
				}
			    }
			}
			System.out.println();
			
			// supposed to get ip route,
			// somewhat like traceroute
			/*
			if (pcappacket.hasHeader(icmp)) {
			    System.out.println("ICMP:\t\t" + icmp.typeEnum());
			} else {
			    System.out.println("No subheaders");
			}
			*/
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
		System.out.println("-");
		System.out.println();
	    }
	};
	pcap.loop(Integer.parseInt(args[0]), pcappackethandler, "pressure");
	pcap.close();
    }
}
