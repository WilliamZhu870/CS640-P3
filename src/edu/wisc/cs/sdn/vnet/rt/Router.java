package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

import java.util.Timer;
import java.util.TimerTask;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	//Variables used in calculating validity in routes. 
	private static final long RIP_RESPONSE_INTERVAL = 10000;
	private static final long ROUTE_TIMEOUT_INTERVAL = 30000;
	private static final int RIP_PORT = UDP.RIP_PORT; //Makes referencing this easier.

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		
		//Initialize routing table and start timer
		initializeRoutingTable();
		startRouteTimeoutTimer();
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

		//RIP packet.
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

	//Handles RIP packets.
	private void handleRipPacket(Ethernet etherPacket, Iface inIface) {
		
		//IDK what these actually do - just reused code from handleIpPacket.
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();

		// Update routing table based on RIP packet
		for (RIPv2Entry entry : ripPacket.getEntries()) {
			int subnet = entry.getAddress() & entry.getSubnetMask();
			int metric = entry.getMetric() + 1; //Add 1 to the hop count.
			int nextHop = ipPacket.getSourceAddress();

			//Check existing entry.
			RouteEntry existingEntry = this.routeTable.lookup(subnet);

			//Update routing table
			if (existingEntry == null || metric < existingEntry.getMetric() || existingEntry.isExpired()) {
				this.routeTable.insert(subnet, nextHop, entry.getSubnetMask(), inIface, metric);

				//Reset the timeout
				RouteEntry updatedEntry = this.routeTable.lookup(subnet);
				updatedEntry.resetTimer();
			}
		}

		//Had a lot of issues here - asked for help from ChatGPT (don't know if it actually does anything.)
		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
			sendRipResponse(inIface);
		}
	}

	private void sendRipResponse(Iface inIface) {
		Ethernet ether = new Ethernet();
		IPv4 ipPacket = new IPv4();
		UDP udpPacket = new UDP();
		RIPv2 ripPacket = new RIPv2();
	
	
		// Check if the interface is null
		if (inIface == null) {
			return;
		}
	
		// Set destination IP to multicast and MAC to broadcast if inIface is null
		if (inIface.getIpAddress() == 0 || inIface.getMacAddress() == null) {
			ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
			ipPacket.setDestinationAddress("224.0.0.9");
		} else {
			// Set destination IP and MAC to the IP address and MAC address of the router interface that sent the request as specified in the assignemnt.
			ether.setDestinationMACAddress(inIface.getMacAddress().toBytes());
			ipPacket.setDestinationAddress(inIface.getIpAddress());
		}
	
		// Set source IP and MAC to interface IP and MAC (got help from ChatGPT for this)
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ipPacket.setSourceAddress(inIface.getIpAddress());
		udpPacket.setSourcePort((short) RIP_PORT);
		udpPacket.setDestinationPort((short) RIP_PORT);
		ripPacket.setCommand(RIPv2.COMMAND_RESPONSE);
		sendPacket(ether, inIface);
	}
	
	//Sends out requests to set everything up & sends unsolicited Rip responses regularly.
	public void startRip() {
		sendRipRequest();

		Timer timer = new Timer();
		timer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				sendUnsolicitedRipResponse();
			}
		}, RIP_RESPONSE_INTERVAL, RIP_RESPONSE_INTERVAL);
	}

	//Sends RIP Request
	private void sendRipRequest() {
		Ethernet ether = new Ethernet();
		IPv4 ipPacket = new IPv4();
		UDP udpPacket = new UDP();
		RIPv2 ripPacket = new RIPv2();

		// Set destination IP to multicast and MAC to broadcast as specified in the assignment
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		ipPacket.setDestinationAddress("224.0.0.9");

		// Set source IP and MAC to interface IP and MAC
		for (Iface iface : this.interfaces.values()) {
			ether.setSourceMACAddress(iface.getMacAddress().toBytes());
			ipPacket.setSourceAddress(iface.getIpAddress());
			udpPacket.setSourcePort((short)RIP_PORT);
			udpPacket.setDestinationPort((short)RIP_PORT);
			ripPacket.setCommand(RIPv2.COMMAND_REQUEST);
			sendPacket(ether, iface);
		}
	}

	//Sends unsolicited RIP response out all interfaces
	private void sendUnsolicitedRipResponse() {
		for (Iface iface : this.interfaces.values()) {
			sendRipResponse(iface);
		}
	}

	//Initializes the routing table.
	private void initializeRoutingTable() {
		for (Iface iface : this.interfaces.values()) {
			int subnet = calculateSubnet(iface.getIpAddress(), iface.getSubnetMask());
			this.routeTable.insert(subnet, 0, iface.getSubnetMask(), iface, 1);
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

	//Got help from ChatGPT with this - apparently it works to check route timeouts. 
	private void startRouteTimeoutTimer() {
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                checkRouteTimeouts();
            }
        }, ROUTE_TIMEOUT_INTERVAL, ROUTE_TIMEOUT_INTERVAL);
    }

	//Used in startRouteTimeoutTimer and helps remove routes that have expired.
	private void checkRouteTimeouts() {
        for (RouteEntry entry : routeTable.getAllEntries()) {
			
			//Skip removing any directly reachable routes.
            if (isDirectlyReachableSubnet(entry.getDestinationAddress(), entry.getMaskAddress())) {
                continue;
            }
            //Remove expired routes.
            if (entry.isExpired()) {
                routeTable.remove(entry.getDestinationAddress());
            }
        }
    }

	//Used in checkRouteTimeouts to ensure that directly reachable routes do not get removed.
    private boolean isDirectlyReachableSubnet(int destination, int mask) {
        for (Iface iface : interfaces.values()) {
            int subnet = calculateSubnet(iface.getIpAddress(), iface.getSubnetMask());
            if (destination == subnet && mask == iface.getSubnetMask()) {
                return true;
            }
        }
        return false;
    }

}
