package cryptography;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

public class DSA_Signer {
	public DSA_Agent dsa_signer;
	
	public DSA_Signer() {
		// TODO Auto-generated constructor stub
	}
	
	public DSA_Signer(String curveFileName) throws IOException {
		// TODO Auto-generated constructor stub
		dsa_signer = new DSA_Agent(curveFileName);
	}
	
	/*public void sendKeyPair(String serverName, int serverPort){
		
	}*/
	
	public void clientMode(String serverName, int serverPort) throws NoSuchAlgorithmException{
		try {
			//1-Connecting to peer/server
			System.out.println("Connecting to "+ serverName + ". . .");
			Socket client = new Socket(InetAddress.getByName(serverName), serverPort);
			System.out.println("Connected to " + client.getRemoteSocketAddress());
			
			//2-Get text and sign
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("Enter message to sign: ");
			String msg = br.readLine();
			String signedMsg = dsa_signer.signMsg(msg);
			
			//3-Send signed message ( = message+signature)
			OutputStream outToServer = client.getOutputStream();
	        DataOutputStream out = new DataOutputStream(outToServer); 
	        out.writeUTF(signedMsg);
	        System.out.println("Sent: "+ signedMsg);
	        
	        //4-Wait for signal before closing
	        String s = "";
	        DataInputStream in = new DataInputStream(client.getInputStream());
	        s = in.readUTF();
	        while(s=="1");
			
	        //5-Close connections
	        client.close();
	        System.out.println("Client socket closed");
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("clientMode error: ");
	    	e.printStackTrace();
		}
	}

}
