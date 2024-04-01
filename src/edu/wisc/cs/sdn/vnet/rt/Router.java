package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import edu.wisc.cs.sdn.vnet.rt.RouteEntry;
import edu.wisc.cs.sdn.vnet.rt.RouteTable;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

import java.util.Timer;
import java.util.TimerTask;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	private static final long RIP_RESPONSE_INTERVAL = 10000; // 10 seconds
	private static final long ROUTE_TIMEOUT_INTERVAL = 30000; // 30 seconds
	private static final int RIP_PORT = UDP.RIP_PORT;

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		initializeRoutingTable();
		startRip();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets */

		switch (etherPacket.getEtherType()) {
			case Ethernet.TYPE_IPv4:
				this.handleIpPacket(etherPacket, inIface);
				break;
			// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		System.out.println("Handle IP packet");

		if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP &&
				((UDP) ipPacket.getPayload()).getDestinationPort() == RIP_PORT) {
			handleRipPacket(etherPacket, inIface);
			return;
		}
		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum) {
			return;
		}

		// Check TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (0 == ipPacket.getTtl()) {
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void handleRipPacket(Ethernet etherPacket, Iface inIface) {
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();

		// Update routing table based on RIP packet
		for (RIPv2Entry entry : ripPacket.getEntries()) {
			int subnet = entry.getAddress() & entry.getSubnetMask();
			int metric = entry.getMetric() + 1; // Adding 1 to metric for hop count
			int nextHop = ipPacket.getSourceAddress(); // Next hop is the source of the RIP packet

			// Lookup existing route entry for the subnet
			RouteEntry existingEntry = this.routeTable.lookup(subnet);

			// If no existing entry, or new entry has lower metric, or entry has timed out,
			// update routing table
			if (existingEntry == null || metric < existingEntry.getMetric() || existingEntry.isExpired()) {
				// Insert or update the route entry
				this.routeTable.insert(subnet, nextHop, entry.getSubnetMask(), inIface, metric);

				// If the route entry is updated, reset the timeout
				RouteEntry updatedEntry = this.routeTable.lookup(subnet);
				updatedEntry.resetTimer();
			}
		}

		// Send RIP response if necessary
		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
			sendRipResponse(inIface);
		}
	}

	private void sendRipResponse(Iface inIface) {
		// Construct RIP response packet
		Ethernet ether = new Ethernet();
		IPv4 ipPacket = new IPv4();
		UDP udpPacket = new UDP();
		RIPv2 ripPacket = new RIPv2();

		// Populate RIP response packet

		// Set destination IP and MAC to multicast and broadcast respectively
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		ipPacket.setDestinationAddress("224.0.0.9");

		// Set source IP and MAC to interface IP and MAC
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ipPacket.setSourceAddress(inIface.getIpAddress());

		// Set UDP source and destination ports to RIP port
		udpPacket.setSourcePort(RIP_PORT);
		udpPacket.setDestinationPort(RIP_PORT);

		// Set RIP command to RESPONSE
		ripPacket.setCommand(RIPv2.COMMAND_RESPONSE);

		// Add RIP entries for reachable subnets via this router

		// Send packet out through the interface
		sendPacket(ether, inIface);
	}

	public void startRip() {
		// Send RIP request out all interfaces when initialized
		sendRipRequest();

		// Send unsolicited RIP response every RIP_RESPONSE_INTERVAL seconds
		Timer timer = new Timer();
		timer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				sendUnsolicitedRipResponse();
			}
		}, RIP_RESPONSE_INTERVAL, RIP_RESPONSE_INTERVAL);
	}

	private void sendRipRequest() {
		// Construct RIP request packet
		Ethernet ether = new Ethernet();
		IPv4 ipPacket = new IPv4();
		UDP udpPacket = new UDP();
		RIPv2 ripPacket = new RIPv2();

		// Populate RIP request packet

		// Set destination IP to multicast and MAC to broadcast
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		ipPacket.setDestinationAddress("224.0.0.9");

		// Set source IP and MAC to interface IP and MAC
		// Send request out all interfaces
		for (Iface iface : this.interfaces.values()) {
			ether.setSourceMACAddress(iface.getMacAddress().toBytes());
			ipPacket.setSourceAddress(iface.getIpAddress());

			// Set UDP source and destination ports to RIP port
			udpPacket.setSourcePort(RIP_PORT);
			udpPacket.setDestinationPort(RIP_PORT);

			// Set RIP command to REQUEST
			ripPacket.setCommand(RIPv2.COMMAND_REQUEST);

			// Send packet out through the interface
			sendPacket(ether, iface);
		}
	}

	private void sendUnsolicitedRipResponse() {
		// Send unsolicited RIP response out all interfaces
		for (Iface iface : this.interfaces.values()) {
			sendRipResponse(iface);
		}
	}

	private void initializeRoutingTable() {
		// Add entries for directly reachable subnets via router's interfaces
		for (Iface iface : this.interfaces.values()) {
			int subnet = calculateSubnet(iface.getIpAddress(), iface.getSubnetMask());
			this.routeTable.insert(subnet, 0, iface.getSubnetMask(), iface);
		}
	}

	private int calculateSubnet(int ipAddress, int subnetMask) {
		return ipAddress & subnetMask;
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch) {
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			return;
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}
}
