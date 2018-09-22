public class DnsResponseHeader {
	int QDCOUNT;
	int ANCOUNT;
	int NSCOUNT;
	int ARCOUNT;
	boolean isAuthoritative;
	
	public DnsResponseHeader(int QDCOUNT, int ANCOUNT, int NSCOUNT, int ARCOUNT, boolean isAuthoritative) {
		this.QDCOUNT = QDCOUNT;
		this.ANCOUNT = ANCOUNT;
		this.NSCOUNT = NSCOUNT;
		this.ARCOUNT = ARCOUNT;
		this.isAuthoritative = isAuthoritative;
	}
}