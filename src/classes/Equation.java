package cryptography;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;

public class Equation {
	public BigInteger p;
	public int sizeOfP;
	public BigInteger a1;
	public BigInteger a2;
	public BigInteger a3;
	public BigInteger a4;
	public BigInteger a6;
	public Point g;
	public BigInteger n;

	public Equation() {
		// TODO Auto-generated constructor stub
	}

	public Equation(BigInteger p, int sizeOfP, BigInteger a1, BigInteger a2, BigInteger a3, BigInteger a4,
			BigInteger a6, Point g, BigInteger n) {
		this.p = p;
		this.sizeOfP = sizeOfP;
		this.a1 = a1;
		this.a2 = a2;
		this.a3 = a3;
		this.a4 = a4;
		this.a6 = a6;
		this.g = g;
		this.n = n;
	}
	
	public Equation(String curveFileName){
		String line;
		BigInteger gx = null, gy = null;
		int lineNumb = 0;
		InputStream f;
		try {
			f = new FileInputStream("./src/wc/"+curveFileName);
			InputStreamReader isr = new InputStreamReader(f, Charset.forName("UTF-8"));
		    BufferedReader br = new BufferedReader(isr);
		    while ((line = br.readLine()) != null) {
		    	switch(lineNumb){
		    	case 0:		//p
		    		this.p = new BigInteger( line.split("=")[1] );
		    		break;
		    	case 1:		//n
		    		this.n = new BigInteger(line.split("=")[1]);
		    		break;
		    	case 2:		//a4
		    		this.a4 = new BigInteger(line.split("=")[1]);
		    		break;
		    	case 3:		//a6
		    		this.a6 = new BigInteger(line.split("=")[1]);
		    		break;
		    	case 6:		//gx
		    		gx = new BigInteger(line.split("=")[1]);
		    		break;
		    	case 7:		//gy
		    		gy = new BigInteger(line.split("=")[1]);
		    		break;
		    	}	
		    	lineNumb++;
		    }
		    this.g= new Point(gx, gy);
		    this.sizeOfP = Integer.parseInt(curveFileName.split("-")[0].split("w")[1]);
		    System.out.println("New weirstrass's equation !");
		    
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	/*
	 * Arithmetics
	 */
	public Boolean contains(Point P){
		//y2
		BigInteger y2 = (P.y).modPow(BigInteger.valueOf(2), this.p);
		//x3
		BigInteger x3 = (P.x).modPow(BigInteger.valueOf(3), this.p);
		//a4*x + a6
		BigInteger a4x = ((P.x).multiply(this.a4)).add(this.a6);
		//
		BigInteger tmp = (x3.add(a4x)).mod(this.p);
		//System.out.println("---"+y2.compareTo(tmp)+"----");
		//Check and return
		return y2.equals(tmp);
	}
	
	public Point oppose(Point P) {
		BigInteger xo = P.x;
		BigInteger yo = ((P.y).negate()).mod(this.p); // -Yp
		
		return new Point(xo, yo);
	}

	public Point doublement(Point P) {
		if(P.isInfinite()){
			return P;
		}else{
			BigInteger typ = ( (P.y).multiply( BigInteger.valueOf(2) ) ).modInverse(this.p) ;
			BigInteger lambda = ( ( ( (P.x).modPow(BigInteger.valueOf(2), this.p) ).multiply(BigInteger.valueOf(3)) ).add(this.a4) ).multiply(typ);
									
			BigInteger xr = ((lambda.modPow(BigInteger.valueOf(2), this.p)).subtract((P.x).multiply(BigInteger.valueOf(2)))).mod(this.p);
			BigInteger yr = ((((P.x).subtract(xr)).multiply(lambda)).subtract(P.y)).mod(this.p);
	
			return new Point(xr, yr);
		}	
	}

	public Point addition(Point P, Point Q) {

		if (P.isInfinite()) {
			return Q;
		} else if (Q.isInfinite()) {
			return P;
		} else if ((this.oppose(P).x == Q.x) && (this.oppose(P).y == Q.y)) {
			return new Point(false); //inf
		} else if (P.isEqualTo(Q)) {
			return this.doublement(P);
		} else {
			BigInteger lambda, X;

			X = (P.x).subtract(Q.x);
			lambda = ((P.y).subtract(Q.y)).multiply(X.modInverse(this.p));

			BigInteger xr = ((((lambda.multiply(lambda)).subtract(P.x)).subtract(Q.x))).mod(this.p);
			BigInteger yr = ((((P.x).subtract(xr)).multiply(lambda)).subtract(P.y)).mod(this.p);

			return new Point(xr, yr);
		}
	}

	public Point multiply(BigInteger n, Point P) {
		if(BigInteger.ZERO.equals(n) || (n == this.n)){
			return new Point(false);
		}
		else{
			Point multpResult;
			String t;

			t = n.toString(2);
			multpResult = new Point(false);
			for (int i = 0; i < t.length() ; i++) {
				multpResult = this.doublement(multpResult);
				if (t.charAt(i) == '1') {
					multpResult = this.addition(P, multpResult);
				}			
			}
			return multpResult;
		}
	}

	/*
	 * End of arithmetics
	 */
	public int getRequestSecurityLength(){
		int N = (this.sizeOfP);
		if (N>=512){
			return 256;			
		}
		else if (N>=384){
			return 192;
		}
		else if (N>=256){
			return 128;
		}
		else if (N>=224){
			return 112;
		}
		else if (N>=160){
			return 80;
		}
		else{
			return -1;
		}
	}

	

}
