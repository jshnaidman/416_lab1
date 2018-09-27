/**
 * UDPClient
 * 
 * Adapted from the example given in Section 2.8 of Kurose and Ross, Computer
 * Networking: A Top-Down Approach (5th edition)
 * 
 * @author michaelrabbat
 * 
 */
import java.io.*;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.ByteBuffer;

import java.util.Random;


public class DnsClient {
	
	static String IP_ADDRESS = "A";
	static String MAIL_SERVER = "MX";
	static String NAME_SERVER = "NX";
	static String DNS_ALIAS = "CNAME";

	private static int parseInt(String str) {
		try {
			return Integer.parseInt(str);
		} catch (NumberFormatException e) {
			System.err.println("ERROR\tNumberFormatException: " + e.getMessage());
			java.lang.System.exit(1);
		}
		// never gets here
		return -1;
	}
	
	private static float parseFloat(String str) {
		try {
			return Float.parseFloat(str);
		} catch (NumberFormatException e) {
			System.err.println("ERROR\tNumberFormatException: " + e.getMessage());
			java.lang.System.exit(1);
		}
		// never gets here
		return -1;
	}
	
	
	private static String parseLabels(ByteBuffer receiveData) throws Exception{
		// get domain name from response
		int labelLength;
		int buf;
		String dnInResponse = "";
		while (true) {
			labelLength = 0xFF & receiveData.get(); 
			//when no more labels, byte will be 0 (null terminated)
			if (labelLength == 0) {
				break;
			}
			// check if pointer
			if ((labelLength>>6 & 0b11)== 0b11) {
				//backup one and getShort to get 16 bit pointer
				receiveData.position(receiveData.position()-1); 
				//0x3FFF because we want to ignore first 2 significant bits
				int pointer = 0x3FFF & receiveData.getShort(); 
				
				// Save the position of the receiveData buffer
				int savedPosition = receiveData.position();
				
				// go to the offset described by pointer
				receiveData.position(pointer);
				
				// recursively parse the labels at that position and return it as a string
				dnInResponse += parseLabels(receiveData);
				
				// readjust the position of the buffer
				receiveData.position(savedPosition);
				
				// return the string
				return dnInResponse;
				
			}
			for (int i=0; i<labelLength;i++) {
				buf = 0xFF & receiveData.get();
				if (buf == 0) {
					throw new Exception("ERROR\tUnexpected null terminating character in the response.\n" + 
				"Domain Name in Response received before exception occurred: " + dnInResponse);
				}
				dnInResponse += (char) buf;
			}
			dnInResponse += ".";
		}
		// remove extra "." in the string from return value
		return dnInResponse.substring(0, dnInResponse.length()-1) ;
	}
	
	// 96 bit header / 12 bytes long
	private static int buildQueryHeader(ByteBuffer sendData, String domainName) {
		Random rand = new Random();
		int input = rand.nextInt(65535);
		int ID = input;
		
		// 16 bit random ID
		sendData.putShort((short) (input & 0xFFFF));
		
		// QR, Opcode, AA, TC are 0
		input = 1; // RD is 1
		sendData.put((byte) (input & 0xFF));
		
		// Z, RCODE, are set to 0
		input = 1<<7; //RA is 1
		sendData.put((byte) (input & 0xFF));
		
		//QDCOUNT is always 1
		sendData.putShort((short) (1 & 0xFFFF));
		
		//ANCOUNT is always 0 
		sendData.putShort((short) (0 & 0xFFFF));
		
		//NSCOUNT is always 0 
		sendData.putShort((short) (0 & 0xFFFF));
		
		//ARCOUNT is always 0 
		sendData.putShort((short) (0 & 0xFFFF));
		return ID;
	}
	
	private static int buildQuery(ByteBuffer sendData, String domainName, int queryType) {
		String[] labels = domainName.split("\\.");
		int length = 0;
		// add each label to the buffer preceded by the length of the label
		for (String label : labels) {
			sendData.put((byte) (label.length() & 0xFF));
			length++;
			for (char c : label.toCharArray()) {
				sendData.put((byte) (c & 0xFF));
				length++;
			}
		}
		sendData.put((byte) 0); // null terminate the domain name		
		sendData.putShort((short) (queryType & 0xFFFF)); // Enter the query Type
		sendData.putShort((short) 1); // The QCLASS is always 0
		
		length += 5; // 1 + 2 + 2 for last 3 lines (byte, short, short)
		
		return length;
		
		
	}
	
	private static DnsResponseHeader parseResponseHeader(ByteBuffer receiveData, int ID) throws Exception{
		// Check the ID
		int buf = (int) 0xFFFF & receiveData.getShort();
		if (ID != buf) {
			throw new Exception("ERROR\tResponse ID does not match query ID.\n"
					+ "Reponse ID: " + String.format("0x%X", buf) +"\n"
					+ "Query ID: " + String.format("0x%X", ID));
		}
		// check flags on next byte
		buf = 0xFF & receiveData.get();
		boolean authoritative = (buf & 1<<2) == 1; // AA flag
		// TC flag (truncation)
		if ((buf & 1<<1) == 1) {
			throw new Exception("ERROR\tResponse was truncated and needs to be retransmitted using TCP");
		}
		
		//check flags on next byte
		buf = 0xFF & receiveData.get();
		if ((buf>>7 & 1) != 1) {
			throw new Exception("ERROR\tRecursive Queries are not supported"); //RA bit should be 1
		}
		
		int RCODE = buf & 0xF; // last 4 bits
		
		switch (RCODE) {
		case 1:
			throw new Exception("ERROR\tFormat Error: The name server was unable to interpret the query");
		case 2:
			throw new Exception("ERROR\tServer Failure: The name server was unable to process this query due to\n" + 
		" a problem with the name server");
		case 3:
			throw new Exception("NOTFOUND");
		case 4:
			throw new Exception("ERROR\tNot implemented: the name server does not support the requested kind of query\n" + 
					"");
		case 5:
			throw new Exception("ERROR\tRefused: the name server refuses to perform the requested operation for policy reasons");
		}
		
		buf = 0xFFFF & receiveData.getShort(); // QDCOUNT
		int ANCOUNT = 0xFFFF & receiveData.getShort(); // ANCOUNT
		int NSCOUNT = 0xFFFF & receiveData.getShort(); // NSCOUNT
		int ARCOUNT = 0xFFFF & receiveData.getShort(); // ARCOUNT
		
		DnsResponseHeader responseHeader = new DnsResponseHeader(buf,ANCOUNT, NSCOUNT, ARCOUNT, authoritative);
		
		return responseHeader;
		
		
	}
	
	private static void parseRecord(ByteBuffer receiveData, boolean isAuthoritative) throws Exception {
		
		/*
		 * Parse the DNS answer
		 */
		
		int buf = -1;
		
		String domainName = parseLabels(receiveData);
		
		int responseType = 0xFFFF & receiveData.getShort();
		String responseTypeString = "";

		switch (responseType) {
		
		case 0x0001: responseTypeString = IP_ADDRESS;
		break;
		
		case 0x0002: responseTypeString = NAME_SERVER;
		break;
		
		case 0x0005:responseTypeString = DNS_ALIAS;
		break;
		
		case 0x000F: responseTypeString = MAIL_SERVER;
		break;
		
		default: throw new Exception("ERROR\tUnexpected RDATA type in the response (" + String.format("%X", responseType)+ ")" );
		
		}
		
		//Class
		buf = 0xFFFF & receiveData.getShort();
		
		if (buf != 1) {
			throw new Exception("ERROR\tQCLASS of response should be 1 (Internet Address) but got " + buf);
		}
		
		long TTL = receiveData.getInt() & 0xFFFFFFFFL;
		
		int RDLENGTH = receiveData.getShort();
		
		String authoritativeString = isAuthoritative ? "auth" : "nonauth";
		
		switch(responseType) {
		case 0x0001:
			if (RDLENGTH != 4) {
				throw new Exception("ERROR\tExpected RDLENGTH to be 4 for type-A record, but got RDLENGTH=" + RDLENGTH);
			}
			String ipString = "";
			for (int i=0;i<3;i++) {
				ipString += Integer.toString((int)(0xFF & receiveData.get())) + ".";
			}
			ipString += Integer.toString((int)(0xFF & receiveData.get()));
			System.out.format("IP\t%s\t%d\t%s%n", ipString,TTL,authoritativeString);
			break;
			
		case 0x0002:
			String nameServerRecord = parseLabels(receiveData);
			System.out.format("NS\t%s\t%d\t%s%n", nameServerRecord,TTL,authoritativeString);
			break;
			
		case 0x0005:
			String alias = parseLabels(receiveData);
			System.out.format("CNAME\t%s\t%d\t%s%n", alias,TTL,authoritativeString);
			break;
			
		case 0x000F:
			int preference = 0xFFFF & receiveData.getShort();
			String exchange = parseLabels(receiveData);
			System.out.format("CNAME\t%s\t%d\t%d\t%s%n", exchange,preference,TTL,authoritativeString);
			break;
		}
	}
	
	public static void main(String args[]) throws Exception
	{
		float timeoutSeconds = 5;
		int maxRetries = 3;
		int serverPort = 53;
		
		int queryType = 0x01;
		String queryTypeString = IP_ADDRESS;
		
		
		byte[] ipAddressBytes = new byte[4];
		String domainName = null;
		
		byte[] responseByteArray;
		
		boolean ipGiven = false;
		boolean dnGiven = false;
		int arxIdx = 0;
		while (arxIdx<args.length) {
			String arg = args[arxIdx];
			
			if (arg.equals("-t")) {
				timeoutSeconds = parseFloat(args[arxIdx+1]);
				arxIdx+= 2;
			}
			else if (arg.equals("-r")) {
				maxRetries = parseInt(args[arxIdx+1]);
				arxIdx+=2;
			}
			else if (arg.equals("-p")) {
				serverPort = parseInt(args[arxIdx+1]);
				arxIdx+=2;
			}
			else if (arg.equals("-mx")) {
				queryType = 0x0F;
				queryTypeString = MAIL_SERVER;
				arxIdx+=1;
			}
			else if (arg.equals("-ns")) {
				queryType = 0x02;
				queryTypeString = NAME_SERVER;
				arxIdx+=1;
			}
			else {
				if (arg.charAt(0) == '@') {
					String[] ipString = arg.split("@")[1].split("\\.");
					if (ipString.length != 4) {
						throw new IllegalArgumentException("ERROR\tIncorrect input syntax: Ip address must be in a.b.c.d format");
					}
					for (int j=0;j<4;j++) {
						ipAddressBytes[j] = (byte) parseInt(ipString[j]);
					}
					ipGiven = true;
					arxIdx++;
				}
				else {
					domainName = arg;
					dnGiven = true;
					arxIdx++;
				}
			}
			
		}
		
		if (!dnGiven) {
			throw new IllegalArgumentException("ERROR\tMissing Input: Missing Required Domain Name argument");
		}
		
		if (!ipGiven) {
			throw new IllegalArgumentException("ERROR\tMissing input syntax: Missing Required Server IP address argument");
		}
		
		

		// Create a UDP socket
		// (Note, when no port number is specified, the OS will assign an arbitrary one)
		DatagramSocket clientSocket = null;
		try {
			clientSocket = new DatagramSocket();
		} catch (Exception e) {
			System.err.println("ERROR\tCouldn't open socket: " + e.getMessage());
			java.lang.System.exit(1);
		}
		//argument is in miliseconds
		clientSocket.setSoTimeout((int) (timeoutSeconds*1000));
		
		
		
		// Resolve a domain name to an IP address object
		// In this case, "localhost" maps to the so-called loop-back address, 127.0.0.1
		InetAddress ipAddress = InetAddress.getByAddress(ipAddressBytes);
		
		// Allocate buffers for the data to be sent and received
		ByteBuffer receiveData = ByteBuffer.allocate(512);
		ByteBuffer sendData = ByteBuffer.allocate(512);
		

		int ID = buildQueryHeader(sendData,domainName);
		int queryLength = buildQuery(sendData,domainName,queryType);
		
		// Create a UDP packet to be sent to the server
		// This involves specifying the sender's address and port number
		DatagramPacket sendPacket = new DatagramPacket(sendData.array(), sendData.array().length, ipAddress, serverPort);
		
		// Send the packet
		
		System.out.format("DnsClient sending request for %s%n", domainName);
		System.out.format("Server: %s%n", ipAddress.getHostAddress());
		System.out.format("Request Type: %s%n", queryTypeString);
		
		int retryCount = 0;
		boolean received = false;
		long startTime = System.nanoTime();
		while(retryCount < maxRetries) {
			try {
				clientSocket.send(sendPacket);
			} catch(Exception e) {
				System.err.println("ERROR\tUnexpected Exception: " + e.getMessage());
				retryCount++;
				continue;
			}
			
			// Create a packet structure to store data sent back by the server
			DatagramPacket receivePacket = new DatagramPacket(receiveData.array(), receiveData.array().length);
			
			// Receive data from the server
			try {
				clientSocket.receive(receivePacket);
				received = true;
				break;
			} catch(java.net.SocketTimeoutException e) {
				System.err.println("ERROR\tSocket Timeout Exception: " + e.getMessage());
			} catch(Exception e) {
				System.err.println("ERROR\tUnexpected Exception: " + e.getMessage());
			} finally {
				retryCount++;
			}
		}
		if (!received) {
			System.out.println("ERROR\tMaximum number of retries [" + maxRetries + "] exceeded");
			java.lang.System.exit(1);
		}
		double responseTimeSeconds = (double) ((System.nanoTime() - startTime)/1e9);
		
		System.out.format("Response received after %f seconds ([%d] retries)%n", responseTimeSeconds, retryCount-1);
		
		DnsResponseHeader responseHeader = parseResponseHeader(receiveData,ID);
		
		receiveData.position(receiveData.position()+queryLength); // ignore query record
		
		if (responseHeader.ANCOUNT > 0) {
			System.out.format("***Answer Section ([%d] records)***%n", responseHeader.ANCOUNT);
		}
		
		for (int i=0; i<responseHeader.ANCOUNT;i++) {
			parseRecord(receiveData, responseHeader.isAuthoritative);
		}
		
		if (responseHeader.ARCOUNT > 0) {
			System.out.format("***Additional Section ([%d] records)***%n", responseHeader.ARCOUNT);
		}
		
		
		for (int i=0; i<responseHeader.ARCOUNT;i++) {
			parseRecord(receiveData, responseHeader.isAuthoritative);
		}
		
		
		
		
		// Close the socket
		clientSocket.close();
	}
}
