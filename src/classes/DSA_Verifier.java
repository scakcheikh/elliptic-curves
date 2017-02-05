package cryptography;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

public class DSA_Verifier extends Thread {
	public DSA_Agent dsa_verifier;
	private ServerSocket serverSocket;
	
	public DSA_Verifier() {
		// TODO Auto-generated constructor stub
	}
	
	public DSA_Verifier(String curveFileName, int port){
		dsa_verifier = new DSA_Agent(curveFileName);
		try {
			serverSocket = new ServerSocket(port);
			//serverSocket.setSoTimeout(10000);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	    
	}
	
	public void run() {
	      while(true) {
	         try {
	            System.out.println("-- DSA signature verifier server --");
	        	System.out.println("Listening mode on port " + serverSocket.getLocalPort() + "...");
	            Socket server = serverSocket.accept();
	            
	            //1-Connected to client
	            System.out.println("Just connected to " + server.getRemoteSocketAddress());
	            
			    //2-Get signed message + signature
	            DataInputStream in = new DataInputStream(server.getInputStream());
	            String rcvd_msg = in.readUTF();
	            System.out.println("Received signed msg:"+ rcvd_msg);
	            Boolean status = dsa_verifier.verifSignature(rcvd_msg);
	            System.out.println("-- Verification status:"+ status+"--");
		        
	            //3-Send closing signal to signer
	            DataOutputStream out = new DataOutputStream(server.getOutputStream());
	            out.writeUTF("status: "+status);
			    
	            //4-Close server
	            server.close();           
	         }catch(IOException | NoSuchAlgorithmException e) {
	            e.printStackTrace();
	            break;
	         }
	      }
	}
	
}
