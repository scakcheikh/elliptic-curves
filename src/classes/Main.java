package cryptography;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class Main {

	public Main() {
		// TODO Auto-generated constructor stub

	}
	// Diffie Hellman server demo program
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		int prgrm = Integer.parseInt(args[0]); // Program number
		String curveFileName = args[1];
		int SERVERPORT = Integer.parseInt(args[2]);
		long SEED = Long.parseLong(args[3]);
		
		switch(prgrm){
		case 1: System.out.println("-- Diffie Hellman demo [Server]--");
				Thread  testServer = new DH_Server(curveFileName, SERVERPORT, SEED);
				testServer.run();
			break;
		case 2: System.out.println("-- Elgamal demo --");
				Thread  testServer2 = new ELGML_Server(curveFileName, SERVERPORT, SEED);
				testServer2.run();
			break;
		case 3: System.out.println("-- Verifying signature (EC-DSA) --");
				//args content: {3 curveFileName SERVERPORT}
				Thread  testServer3 = new DSA_Verifier(curveFileName, SERVERPORT);
				testServer3.run();
				
			break;
		case 4:	System.out.println("-- Sign a message (EC-DSA) --");
				//args content: {4 curveFileName signatureFilePath}
				try {
					DSA_Signer dsa_signer =  new DSA_Signer(curveFileName);
					dsa_signer.clientMode("127.0.0.1", SERVERPORT);
				} catch (IOException | NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}			
			break;
		case 5:	System.out.println("-- Generate EC-DSA Key pair --");
				//args content: {5 curveFileName - - keyFilName}
				String keyFileName = args[4];
				DSA_Agent dsa_keyGen =  new DSA_Agent(curveFileName);
				try {
					dsa_keyGen.generateKeyPair(keyFileName);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			break;
		case 6: System.out.println("-- Station-to-Station Protocol --");
				Thread  testServer4 = new STS_Server(curveFileName, SERVERPORT);
				testServer4.run();
			break;
		}
		
		System.out.println( "--Program halted---");
		
	}

}
