package cryptography;

import java.math.BigInteger;
import java.net.ServerSocket;
import java.util.Random;

public class ELGML_Agent {
	private BigInteger privateKey; // x or h
	public Point publicKey; // y = xg
	public Point foreignPublicKey; //y from bob
	public Point c1;// hg
	public BigInteger c2; // f(m) + hy
	public String msg;
	private Equation w;
	private ServerSocket serverModeSocket;
	

	public ELGML_Agent() {
		// TODO Auto-generated constructor stub
	}
	
	public ELGML_Agent(String curveFileName, long seed) {
		this.w = new Equation(curveFileName);
		Random rnd = new Random(seed);
		this.privateKey = new BigInteger(this.w.sizeOfP, rnd);
	}

	public void generatePublicKey() {
		this.publicKey = w.multiply(this.privateKey, w.g); //xg
	}
	
	public Point generateC1(){
		return (w.multiply(this.privateKey, w.g)); // hg , 	
	}
		
	public BigInteger generateC2(){
		//Change message to decimal
		BigInteger enc_msg = toBigInteger(this.msg); // f(m)
		BigInteger hy = (this.w.multiply(this.privateKey ,this.foreignPublicKey)).x;
		this.c2 = enc_msg.add(hy);
		
		return c2;
	}
	
	public String sendPublicKeyString(){
		return this.publicKey.pointToString();
	}

	public String sendC1C2(){
		String s = this.generateC1().pointToString()+":"+this.c2.toString();
		return s;
	}
	
	public void recoverMsg(String cphrd){
		this.c1 = new Point((cphrd.split(":")[0]).split(";")[0], (cphrd.split(":")[0]).split(";")[1], "true");
		this.c2 = new BigInteger(cphrd.split(":")[1]);
		
		BigInteger xC1 = (this.w.multiply(this.privateKey, this.c1)).x;
		this.msg = fromBigInteger((this.c2).subtract(xC1));
		
		System.out.println("received c1: "+this.c1);
		System.out.println("received c2: "+this.c2);
		
		System.out.println("Recovered Message: ");
		System.out.println("---"+this.msg+"---");
		return;
	}
	
	
	/*--------------------- Utils ----------------*/
	public static BigInteger toBigInteger(String foo)
	{
	    return new BigInteger(foo.getBytes());
	}
	
	public String fromBigInteger(BigInteger bar)
	{
	    return new String(bar.toByteArray());
	}
}
