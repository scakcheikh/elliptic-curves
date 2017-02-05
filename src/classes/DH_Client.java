package cryptography;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public class DH_Client {
	public DH_Agent dh_client;
	
	public DH_Client(String curveFileName, long seed) {
		// TODO Auto-generated constructor stub
		dh_client = new DH_Agent(curveFileName, seed);
		
	}

	public void clientMode(String serverName, int serverPort){
		
		try {
			//1-Connecting to peer/server
			System.out.println("Connecting to "+ serverName + ". . .");
			Socket client = new Socket(InetAddress.getByName(serverName), serverPort); // For sending key
			System.out.println("Connected to " + client.getRemoteSocketAddress());
			
			//Compute publicKey
			dh_client.generatePublicKey();
			
			//2-Send publickey
			OutputStream outToServer = client.getOutputStream();
	        DataOutputStream out = new DataOutputStream(outToServer); 
	        out.writeUTF(dh_client.stringToSend());
	        System.out.println("Sent public key: "+ dh_client.stringToSend());

	        //3-Wait for server's public key
	        DataInputStream in = new DataInputStream(client.getInputStream());
	        String s = in.readUTF();
	        dh_client.foreignPublicKey = new Point(s.split(";")[0], s.split(";")[1], s.split(";")[2]);
	        System.out.println("foreignPublicKey: "+ s);
            
	        //4-generate secretkey
	        dh_client.generateSecretKey();
	        System.out.println("secretKey: "+ dh_client.getSecretKey());
	        
	        //5-Close connections
	        client.close();
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("clientMode error: ");
	    	e.printStackTrace();
		}
	}
}
