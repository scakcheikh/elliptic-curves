package cryptography;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public class ELGML_Client {
	public ELGML_Agent elgml_client;
	
	public ELGML_Client() {
		// TODO Auto-generated constructor stub
	}
	
	public ELGML_Client(String curveFileName, long seed) {
		// TODO Auto-generated constructor stub
		elgml_client = new ELGML_Agent(curveFileName, seed);	
	}

	public void clientMode(String serverName, int serverPort){
		try {
			//1-Connecting to peer/server
			System.out.println("Connecting to "+ serverName + ". . .");
			Socket client = new Socket(InetAddress.getByName(serverName), serverPort); // For sending key
			System.out.println("Connected to " + client.getRemoteSocketAddress());
			
			//2-Wait for server's public key
	        DataInputStream in = new DataInputStream(client.getInputStream());
	        String s = in.readUTF();
	        elgml_client.foreignPublicKey = new Point(s.split(";")[0], s.split(";")[1], s.split(";")[2]);
	        System.out.println("-- //------------------------------// --");
	        System.out.println("Server's Public Key: "+ s);
	        System.out.println("-- //------------------------------// --");
	        
	        //3-Compute publicKeys
			elgml_client.generateC1();
			
			//4- Get text to cipher 
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("Enter message: ");
			elgml_client.msg = br.readLine();
			elgml_client.generateC2();
			
			//5-Send public keys c1 & c2
			OutputStream outToServer = client.getOutputStream();
	        DataOutputStream out = new DataOutputStream(outToServer); 
	        String tmp = elgml_client.sendC1C2(); 
	        out.writeUTF(tmp);
	        System.out.println("Sent public key: "+ tmp);
	        
	        System.out.println("-- //------------------------------// --");
	        System.out.println("-- Halting client . . . --");
	        //6-Close connections
	        client.close();
	        System.out.println("-- Client halted ! --");
	        
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("clientMode error: ");
	    	e.printStackTrace();
		}
	}


}
