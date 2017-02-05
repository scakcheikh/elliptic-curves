package cryptography;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ELGML_Server extends Thread {
	private ServerSocket serverSocket;
	public ELGML_Agent elgml_server;
	
	public ELGML_Server() {
		// TODO Auto-generated constructor stub
	}
	
	public ELGML_Server(String curveFileName, int port, long seed){
		elgml_server = new ELGML_Agent(curveFileName, seed);
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
	            System.out.println("-- Elgamal program server --");
	        	System.out.println("Waiting to hear from client on port " + serverSocket.getLocalPort() + "...");
	            Socket server = serverSocket.accept();
	            
	            //1-Connected to client
	            System.out.println("Just connected to " + server.getRemoteSocketAddress());
	            System.out.println("-- //------------------------------// --");
		        
	            //2-Compute publicKey
	            elgml_server.generatePublicKey();
	            System.out.println("Current machine's publicKey: "+ elgml_server.publicKey.pointToString());
	            System.out.println("-- //------------------------------// --");
		        
	            //3-Send publicKey to client
	            DataOutputStream out = new DataOutputStream(server.getOutputStream());
	            out.writeUTF(elgml_server.sendPublicKeyString());
			    
			    //4-Get public Keys C1 & C2 from client
	            DataInputStream in = new DataInputStream(server.getInputStream());
	            String cphrd = in.readUTF();
	            System.out.println("Received ciphered msg: " + cphrd);
	            System.out.println("-- //------------------------------// --");
		        elgml_server.recoverMsg(cphrd);
		        System.out.println("-- //------------------------------// --");
		        
	            //5-Close server
	            server.close();
	            
	         }catch(IOException e) {
	            e.printStackTrace();
	            break;
	         }
	      }
	}
}
