package cryptography;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class DH_Server extends Thread {
	private ServerSocket serverSocket;
	public DH_Agent dh_server;
	
	public DH_Server(String curveFileName, int port, long seed){
		dh_server = new DH_Agent(curveFileName, seed);
		// TODO Auto-generated constructor stub
		
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
	            System.out.println("Waiting to hear from client on port " + 
	               serverSocket.getLocalPort() + "...");
	            Socket server = serverSocket.accept();
	            
	            //1-Connected to client
	            System.out.println("Just connected to " + server.getRemoteSocketAddress());
	            
	            //2-Compute publicKey
	            dh_server.generatePublicKey();
	            System.out.println("Server's publicKey: "+ dh_server.publicKey);
		        
	            //3-Send publicKey to client
	            DataOutputStream out = new DataOutputStream(server.getOutputStream());
	            out.writeUTF(dh_server.stringToSend());
			    System.out.println("Sent public key: "+ dh_server.stringToSend());
			    
			    //4-Get publicKey from client
	            DataInputStream in = new DataInputStream(server.getInputStream());
	            String s = in.readUTF();
	            dh_server.foreignPublicKey = new Point(s.split(";")[0], s.split(";")[1], s.split(";")[2]);
		        System.out.println("foreignPublicKey: "+ s);
		        
		        //5-generate secretkey
		        dh_server.generateSecretKey();
		        System.out.println("secretKey: "+ dh_server.getSecretKey());
		        
	            //Close server
	            server.close();
	            
	         }catch(IOException e) {
	            e.printStackTrace();
	            break;
	         }
	      }
	}
	
	

	
}
