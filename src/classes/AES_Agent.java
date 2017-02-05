package cryptography;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_Agent {
	public byte[] key;
	public byte[] initVectorBytes;
	public byte[] ivToSend;
	public int AES_KEY_SIZE = 128;
	
	public AES_Agent(BigInteger key){
		//Hash message (H(m)) using SHA-256
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(key.toByteArray());
			this.key = Arrays.copyOf(messageDigest.digest(), AES_KEY_SIZE / Byte.SIZE);
			
			SecureRandom random = new SecureRandom();
		    initVectorBytes = new byte[16];
			random.nextBytes(initVectorBytes);
		    //System.out.println("AES key: "+(this.key)+"\n key lenght: "+this.key.length+"\niv: "+initVectorBytes+"\niv length: "+initVectorBytes.length);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public String encrypt(String msg) {
        try {
            IvParameterSpec iv = new IvParameterSpec(this.initVectorBytes);
            SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(msg.getBytes());
            //System.out.println("AES encrypted string: "+ Base64.getEncoder().encodeToString(encrypted));

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public String decrypt(String encrypted) {
        try {
            //IvParameterSpec iv = new IvParameterSpec(init_vector.getBytes("UTF-8"));
           // SecretKeySpec skeySpec = new SecretKeySpec(this.key.getBytes("UTF-8"), "AES");
        	IvParameterSpec iv = new IvParameterSpec(this.initVectorBytes);
            SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
            this.ivToSend = iv.getIV();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
    
    /*--------------------- Utils ----------------*/
	public static BigInteger toBigInteger(String foo) throws UnsupportedEncodingException
	{
	    return new BigInteger(foo.getBytes("UTF-8"));
	}
	
	public static String fromBigInteger(BigInteger bar)
	{
	    return new String(bar.toByteArray());
	}

}
