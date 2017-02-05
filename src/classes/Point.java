package cryptography;

import java.math.BigInteger;

public class Point {
	public BigInteger x;
	public BigInteger y;
	public boolean c3;

	public Point() {
		// TODO Auto-generated constructor stub
		this.c3 = true;
	}

	public Point(boolean a) { //infinite
		// TODO Auto-generated constructor stub
		this.x = new BigInteger("0");
		this.y = new BigInteger("1");
		this.c3 = false;
		
	}

	public Point(BigInteger x, BigInteger y) {
		// TODO Auto-generated constructor stub
		this.x = x;
		this.y = y;
		this.c3 = true;
	}
	
	public Point(String x, String y, String c3) {
		// TODO Auto-generated constructor stub
		this.x = new BigInteger(x);
		this.y = new BigInteger(y);
		this.c3 = Boolean.parseBoolean(c3);
	}

	public boolean isEqualTo(Point Q) {
		return (this.x.equals(Q.x) && this.y.equals(Q.y) && this.c3 == Q.c3);
	}


	public boolean isInfinite() {
		return !this.c3;
	}

	public String pointToString(){
		return new String(this.x + ";" + this.y + ";" + this.c3);
	}
	
	public Point stringToPoint(String s){
		return new Point(s.split(";")[0], s.split(";")[1], s.split(";")[2]);
	}
	
	public void printPoint() {
		System.out.println("x= " + this.x);
		System.out.println("y= " + this.y);
		System.out.println("c3= " + this.c3);

		return;
	}
}
