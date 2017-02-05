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
import java.util.Arrays;
import java.util.Base64;

public class STS_Client {
	public STS_Agent sts_client;
	public DH_Agent dh_client;
	public DSA_Agent dsa_client;
	public AES_Agent aes_client;
	public STS_Client() {
		// TODO Auto-generated constructor stub
	}
	
	public STS_Client(String curveFileName){
		sts_client = new STS_Agent(curveFileName);
		dh_client = sts_client.dh_agent;
		dsa_client = sts_client.dsa_agent;
		
	}
	
	public void clientMode(String serverName, int serverPort){
		try{
			//1-Connecting to peer/server
			System.out.println("Connecting to "+ serverName + ". . .");
			Socket client = new Socket(InetAddress.getByName(serverName), serverPort); // For sending key
			System.out.println("Connected to " + client.getRemoteSocketAddress());
			
			//2- Computes DH public and send to server
			this.dh_client.generatePublicKey();
			OutputStream outToServer = client.getOutputStream();
	        DataOutputStream out = new DataOutputStream(outToServer); 
	        out.writeUTF(dh_client.stringToSend());
	        System.out.println("Sent DH public key: "+ dh_client.stringToSend());
	        
			//3- Wait for Data from server
	        DataInputStream in = new DataInputStream(client.getInputStream());
	        String s = in.readUTF();
	        //System.out.println("Received data: "+ s);
	        //s format: (Ek(sign(Pb:Pa)):Pb)
	        String fk = s.split(":")[1];   //What if  encrypted contains ":", that will fake the split(":")
	        dh_client.foreignPublicKey = new Point(fk.split(";")[0], fk.split(";")[1], fk.split(";")[2]);
	        //System.out.println("foreignPublicKey: "+ dh_client.foreignPublicKey.pointToString());
	        
			//4- Compute DH secret
			dh_client.generateSecretKey();
			aes_client = new AES_Agent(dh_client.getSecretKeyPoint().x);
			
			//5- Decrypt & verify signature
				//Decrypt
			String str_encrptd = s.split(":")[0];
			byte[] initVect64 = Base64.getDecoder().decode(s.split(":")[2]);
			byte[] initVector = Arrays.copyOf(initVect64, 128 / Byte.SIZE);
			aes_client.initVectorBytes = initVector;
			//System.out.println("\niv: "+aes_client.initVectorBytes+"\niv length: "+aes_client.initVectorBytes.length);

			String strSgntr = aes_client.decrypt(str_encrptd);	
			strSgntr = strSgntr.substring(0, strSgntr.length() - 1);//To remove last ":" character
			//System.out.println("Recovered signature: "+ strSgntr);
			//Verify sign
			Boolean sign_status = dsa_client.verifSignature(strSgntr);	
			//Proceed if TRUE	
			if(sign_status){
				System.out.println("Server authentication Ok !");	
				//6- Concatenates, sign and encrypt
				String strToSign = dh_client.publicKey.pointToString()+","
							+dh_client.foreignPublicKey.pointToString();
				//System.out.println("strToSign: "+ strToSign);
				//Sign
				String strToEncrypt = dsa_client.signMsg(strToSign);
				//System.out.println("Signed: "+strToEncrypt);
				//Encrypt
				String strEncrptd = aes_client.encrypt(strToEncrypt);
				//7- Send encrypt
				//String dataToSend = strEncrptd;
	            DataOutputStream out2 = new DataOutputStream(client.getOutputStream());
	            out2.writeUTF(strEncrptd);
			   	
	            //8-Wait for final ok
	            DataInputStream in2 = new DataInputStream(client.getInputStream());
		        String s2 = in2.readUTF();
		        System.out.println("Received message: "+ s2);
		        if(s2.equals("OK")){
		        	System.out.println("Trust established");
		        }
		        String end;
		        do{
		        	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		        	System.out.println("Type (q) to quit !");
					end = br.readLine();
				}while(true);
				
			}
			else{
				System.out.println("Signature check failed ! Aborting connection . . .");
			}
			//9-Close connection
			client.close();
		
		}catch (IOException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			System.out.println("clientMode error: ");
	    	e.printStackTrace();
		}
	}
	

}
