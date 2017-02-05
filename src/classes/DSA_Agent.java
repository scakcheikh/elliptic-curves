package cryptography;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;



public class DSA_Agent {
	private String prvKeyFile;//s
	public String pubKeyFile; //Q
	public Equation w;
	/*----*/
	
	public DSA_Agent() {
		// TODO Auto-generated constructor stub
	}
	
	public DSA_Agent(String curveFileName) {
		this.w = new Equation(curveFileName);
		
	}
	
	public void generateKeyPair(String keyFileName) throws IOException {
		System.out.println("DSA's key pair generation . . .");
		int reqstd_secu_length = this.w.getRequestSecurityLength();
		if(reqstd_secu_length<0){
			System.out.println("Not a secure length");
		}
		//Random seed;
		SecureRandom random = new SecureRandom();
	    random.generateSeed(reqstd_secu_length+64);
	    BigInteger c = new BigInteger(reqstd_secu_length+64, random);
	    
	    //Compute s, privatKey = (c mod (n-1))+1
		BigInteger privateKey = (c.mod((this.w.n).subtract(BigInteger.valueOf(1)))).add(BigInteger.valueOf(1));
		//System.out.println("privateKey < n: "+ privateKey.compareTo(this.w.n) +"\n numBits: "+ privateKey.bitCount());
		//Compute  Q = sP
		Point publicKey = this.w.multiply(privateKey, this.w.g);
		//Check that w contains Q
		//System.out.println("w contains Q?: "+this.w.contains(publicKey));
		//toString for later save in file
		String str_prvKey = privateKey.toString(); //s
		String str_pubKey = (publicKey).pointToString();//Q = sP
		System.out.println("-- //------------------------------// --");
        System.out.println("Generated keys:\nprivate key: "+str_prvKey +"\npublic key: "+str_pubKey);		
        System.out.println("-- //------------------------------// --");
        
		//Save key pair in files
		String keyFolder = "./src/keys/";
		this.prvKeyFile = keyFolder + keyFileName+".ecdsakey";
		this.pubKeyFile = keyFolder + keyFileName+"_pub.ecdsakey";
		File prv_file = new File(prvKeyFile);
		File pub_file = new File(pubKeyFile);
	    
		// create the files
	    prv_file.createNewFile();
	    pub_file.createNewFile();
	      
	    // creates a FileWriter Object
	    FileWriter prvK_wrter = new FileWriter(prv_file); 
	    FileWriter pubK_wrter = new FileWriter(pub_file); 
      
	    // Writes the content to the files
	    try {
			//pubK_wrter.write(pubKey_encoded);
	    	pubK_wrter.write(str_pubKey);
	    	prvK_wrter.write(str_prvKey);
	    	pubK_wrter.flush();
		    pubK_wrter.close();
		    prvK_wrter.flush();
	    	prvK_wrter.close();
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Writing Key file error: ");
			e.printStackTrace();
		} 	     
	    System.out.println("keyPair generated and saved at "+ keyFolder);	
	}
	
	
	//Signature method
	public String signMsg(String msg) throws NoSuchAlgorithmException, IOException{
		System.out.println("Signing process started . . .");
		boolean next_turn = true;
		BigInteger k, u = null, v = null;
		int reqstd_secu_length = this.w.getRequestSecurityLength();
		
		if(reqstd_secu_length<0){
			System.out.println("Not a secure length");
		}
		//Hash message (H(m)) using SHA-256
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(msg.getBytes("UTF-8"));
		byte[] t = messageDigest.digest();
		BigInteger hshd_bigInt = new BigInteger(t);
		System.out.println("hashed_message's BigInteger : "+ hshd_bigInt);
		SecureRandom random = new SecureRandom();
		do{
			//Choose k
			byte bytes[] = new byte[reqstd_secu_length];
			random.nextBytes(bytes);
		    BigInteger c = new BigInteger(reqstd_secu_length, random);
		    BigInteger nM2 = (this.w.n).subtract(BigInteger.valueOf(2));
		    if(c.compareTo(nM2)==1){
		    	continue;
		    }else{
		    	k = c.add(BigInteger.valueOf(1));//k = c+1
		    }
		    //System.out.println("privateKey < n: "+ k.compareTo(this.w.n) +"\n numBits: "+ k.bitCount());
			
			Point tmp = this.w.multiply(k, this.w.g);//Compute kP;
			u = (tmp.x).mod(this.w.n);
			if(BigInteger.ZERO.equals(u)){
				continue;
			}
			//Get private Key		
			do{
				this.prvKeyFile ="";
				BufferedReader bfr = new BufferedReader(new InputStreamReader(System.in));
				System.out.println("Enter private key filename: ");
				this.prvKeyFile = bfr.readLine();				
			}while(this.prvKeyFile == "");
			
			FileInputStream f = new FileInputStream("./src/keys/"+this.prvKeyFile+".ecdsakey");
			InputStreamReader isr = new InputStreamReader(f, Charset.forName("UTF-8"));
		    BufferedReader br = new BufferedReader(isr);
		    BigInteger prv_key = new BigInteger(br.readLine());
		    br.close();
			BigInteger su = prv_key.multiply(u);// s*u
			BigInteger k_inv = k.modInverse(this.w.n);
			v = ((hshd_bigInt.add(su)).multiply(k_inv)).mod(this.w.n);// [H(m)+su]/k
			if(BigInteger.ZERO.equals(v)){
				continue;
			}
			next_turn = false;
		}while(next_turn);  	
		
		String msg_sgn = u.toString()+";"+v.toString()+":"+msg+":";
		
		System.out.println("Signature generated ! ");
	    return msg_sgn;
	}
	
	//Verification method
	public boolean verifSignature(String msgAndsgn) throws NoSuchAlgorithmException, IOException{
		//Get public Key Q
		String pbkFilename = "";
		do{
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("Enter public Key filename: ");
			pbkFilename = br.readLine();
		}while(pbkFilename == "");
		
	    FileInputStream ff = new FileInputStream("./src/keys/"+pbkFilename+".ecdsakey");
		InputStreamReader isrr = new InputStreamReader(ff, Charset.forName("UTF-8"));
	    BufferedReader brr = new BufferedReader(isrr);
	    String Q_str = brr.readLine();
	    //System.out.println("Public key read: "+ Q_str);
	    Point Q = new Point(Q_str.split(";")[0], Q_str.split(";")[1], "true");
	    
		//Check Q != inf and nQ = inf
		Point inf = new Point(false); // infinite point
		if(inf.isEqualTo(Q) || !inf.isEqualTo(w.multiply(w.n, Q))){
			return false;
		}
		//Check Q € E(K)
		//System.out.println("Q_str: "+Q.pointToString()+"\ntest: "+ this.w.contains(Q));
		if(!this.w.contains(Q)){
			return false;
		}
		//Get signature
		
		String rcvd_msg = msgAndsgn.split(":")[1];
		//System.out.println("rcvd_msg: "+rcvd_msg);
		String sgn = msgAndsgn.split(":")[0];
		Point uv = new Point(sgn.split(";")[0], sgn.split(";")[1], "true");
	    //System.out.println("uv: "+uv.pointToString()+"\nMessage: "+rcvd_msg);
		//- check uv components
		if(belongsTo(uv, this.w.n)){
			//Hash message (H(m)) using SHA-256
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(rcvd_msg.getBytes("UTF-8"));
			byte[] hshd_msg = messageDigest.digest();
			BigInteger hshd_BigInt = new BigInteger(hshd_msg);
			//System.out.println("hshd_BigInt: "+hshd_BigInt);
			//String result = (hshdBig.compareTo(hshd_BigInt) == 0) ? "EQUAL":"DIFFERENT";
			//System.out.println("Compare hashes: "+ result);
			//System.out.println("Hashed Mod: "+ hshd_BigInt);
			//Compute (x,y)
			BigInteger v_inv = (uv.y).modInverse(this.w.n);// 1/v
			BigInteger tmp1 = (hshd_BigInt).multiply(v_inv);// H(m)/v
			tmp1 = (tmp1.mod(this.w.n)); //(H(m)/v)mod n
			Point tmp_uv = this.w.multiply(tmp1, this.w.g);//(H(m)/v)P
			BigInteger tmp2 = ((uv.x).multiply(v_inv)).mod(this.w.n);// (u/v)mod n
			Point tmp_uv2 = this.w.multiply(tmp2, Q);//(u/v mod n)Q
			tmp_uv = w.addition(tmp_uv, tmp_uv2);
			
			// Check u = x modn
			return (uv.x).equals((tmp_uv.x).mod(this.w.n));
		}
		return false;		 		
	}
	
	/*--------------------- Utils ----------------*/
	// checks that P.x and P.y belongs to [1, n-1[
	public boolean belongsTo(Point P, BigInteger n){
		 
		int result = (
			 (P.x).compareTo(BigInteger.valueOf(1)) +
			 (P.x).compareTo(n) +
			 (P.y).compareTo(BigInteger.valueOf(1)) +
			 (P.y).compareTo(n)
		 ) ;
		
		 return (result == 0)||(result == -2);
	}

}
