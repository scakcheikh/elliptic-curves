package cryptography;

import java.math.BigInteger;

public class STS_Agent {
	public DSA_Agent dsa_agent;
	public DH_Agent dh_agent;
	/* Signature variables*/
	private BigInteger prv_key;
	public Point pub_key;
	/* Shared key establishment variables*/
	private BigInteger dh_prv_key; // a
	public Point dh_pub_key; // aP
	public Point frgn_pub_key;// bP
	private Point scrt_key; // abP
	
	public STS_Agent() {
		// TODO Auto-generated constructor stub
	}
	
	public STS_Agent(String curveFileName) {
		// TODO Auto-generated constructor stub
		//Initialise equation
		
		//Generate DSA Key Pair
		dsa_agent = new DSA_Agent(curveFileName);
		//Generate DH Key establishment parameters
		dh_agent = new DH_Agent(curveFileName, 45);
		//AES encryption parameters init
	}
	
	
}
