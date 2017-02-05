package cryptography;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Random;

public class DH_Agent {

	private BigInteger privateKey; // a
	public Point publicKey; // aP
	public Point foreignPublicKey;// bP
	private Point secretKey; // abP
	private Equation w;
	private ServerSocket serverModeSocket;

	public DH_Agent(String curveFileName, long seed) {
		this.w = new Equation(curveFileName);
		//Random rnd = new Random(seed);
		SecureRandom rnd = new SecureRandom();
	    rnd.generateSeed(this.w.sizeOfP+1);
	    privateKey = new BigInteger(this.w.sizeOfP+1, rnd);
	}

	public void generatePublicKey() {
		this.publicKey = w.multiply(this.privateKey, w.g);
		//return this.publicKey;
	}
	
	public void generateSecretKey(){
		this.secretKey = w.multiply(this.privateKey, this.foreignPublicKey);
	}
	
	public Point getSecretKeyPoint(){
		return this.secretKey;
	}
	
	public String getSecretKey(){
		return secretKey.pointToString();
	}
	
	public String stringToSend(){
		return this.publicKey.pointToString();
	}
		
}
