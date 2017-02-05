package cryptography;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class STS_Server extends Thread {
	private ServerSocket serverSocket;
	public STS_Agent sts_server;
	public DH_Agent dh_server;
	public DSA_Agent dsa_server;
	public AES_Agent aes_server;
	
	public STS_Server() {
		// TODO Auto-generated constructor stub
	}
	
	public STS_Server(String curveFileName, int port){
		sts_server = new STS_Agent(curveFileName);
		// TODO Auto-generated constructor stub
		dh_server = sts_server.dh_agent;
		dsa_server = sts_server.dsa_agent;
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
	            
	            //!- compute DH public key
	            dh_server.generatePublicKey();
	            
	            //2-Wait DH public from client
	            DataInputStream in = new DataInputStream(server.getInputStream());
	            //String s = in.readUTF();
	            String s = in.readUTF();
	            
	            dh_server.foreignPublicKey = new Point(s.split(";")[0], s.split(";")[1], s.split(";")[2]);
		        //System.out.println("Received client's DH Public key: "+ s);
		        
	            //3- Compute DH secret key 
	            dh_server.generateSecretKey();
	            aes_server = new AES_Agent(dh_server.getSecretKeyPoint().x);
	            
	            //4- Concatenate, and encrypt sign
	            	//Concat
	            String strToSign = dh_server.publicKey.pointToString()+","
	            					+dh_server.foreignPublicKey.pointToString();
	            //System.out.println("strToSign: "+ strToSign);
	            	//Sign
	            String strToEncrypt = dsa_server.signMsg(strToSign);
	            //System.out.println("Signed: "+strToEncrypt);
	            	//Encrypt
	            String strEncrptd = aes_server.encrypt(strToEncrypt);
	            
	            //5- Send (encrypted + DH public key)
	            String initVect64 = Base64.getEncoder().encodeToString(aes_server.initVectorBytes);
	            String dataToSend = strEncrptd+":"+dh_server.publicKey.pointToString()+":"
	            		+initVect64;
                DataOutputStream out = new DataOutputStream(server.getOutputStream());
	            out.writeUTF(dataToSend);
			    
	            //6- Wait for Data
	            DataInputStream in2 = new DataInputStream(server.getInputStream());
		        String s2 = in.readUTF();		        
	            //7- Decrypt & verify signature
	            String strSgntr = aes_server.decrypt(s2);
				strSgntr = strSgntr.substring(0, strSgntr.length() - 1);//To remove last ":" character
	            //System.out.println("Recovered signature: "+ strSgntr);
	            //Verify signature
	            Boolean check_status = dsa_server.verifSignature(strSgntr);
	            if(check_status){
	            	System.out.println("Client authentication Ok !");	
					//Send final Ok to client
	            	DataOutputStream out2 = new DataOutputStream(server.getOutputStream());
		            out2.writeUTF("OK");				    
	            }else{
	            	System.out.println("Client authentication failed ! Aborting connection . . .");
	            }
 	            //[8- Close server]
	            server.close();
	            
	         }catch(IOException | NoSuchAlgorithmException e) {
	            e.printStackTrace();
	            break;
	         }
	      }
	}

}
