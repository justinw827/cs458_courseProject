import java.net.*;
import java.io.*;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.security.spec.*;

public class VoterCli {
    // initialize socket and input output streams
    private SSLSocket        socket  = null;
    private BufferedReader   input   = null;
    private PrintWriter		 out     = null;
    private BufferedReader   serverOutput = null;

    private PrivateKey priv;
    private PublicKey pub;
 
    // Constructor to put ip address and port
    public VoterCli(String address, int port) {
        // establish a connection
        try {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) sslsocketfactory.createSocket(address, port);
            System.out.println("Connected");
 
            // Create buffered reader to get input from console
            input = new BufferedReader(new InputStreamReader(System.in));
 	
            // Sends output to the socket
            out = new PrintWriter(socket.getOutputStream(), true);
        } catch(UnknownHostException u) {
            u.printStackTrace();
			System.err.println("Error connecting to server.");
        } catch(IOException i) {
            i.printStackTrace();
			System.err.println("Error connecting to server.");
        }
 
 

	    try {

            // Generate Public and Private Key for Voter Client
            generateKeyPairs();

	        // Get name
			System.out.println("Enter name.");
			String name = input.readLine();

			// Get vNumber
			System.out.println("Enter voter registration number.");
			String vNumber = input.readLine();

            // Digitally sign the name
            // Digital Signature code found here: https://docs.oracle.com/javase/tutorial/security/apisign/step3.html
            Signature dsa = Signature.getInstance("SHA1withRSA");
            dsa.initSign(priv);

            byte[] nameBuff = name.getBytes();
            dsa.update(nameBuff, 0, nameBuff.length);

            byte[] realSig = dsa.sign();

            /* save the signature in a file */
            // Source: https://docs.oracle.com/javase/tutorial/security/apisign/step4.html
            FileOutputStream sigfos = new FileOutputStream("digitalSignature");
            sigfos.write(realSig);
            sigfos.close();

			// Encrypt name, vNumber, and digital signature using server's public key into one message
            PublicKey serverPubKey = readPublicKey("serverPubKey.der");

            String sMessage = name + ":" + vNumber + ":" + realSig.toString();
            byte[] message = encrypt(serverPubKey, sMessage);

            // Send encrypted message
	        out.println(message.toString());

	        // Get response from server
	        serverOutput = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	        String response = "";
	        while ((response = serverOutput.readLine()) != null) {
	        	System.out.println(response);
	        }    

	        if (response == "OK") {
	        	System.out.println("the vNumber is correct");
	        } else {
	        	System.out.println("the vNumber is incorrect");
	        }

	    } catch (IOException e) {
	        e.printStackTrace();
			System.err.println("Error while reading input.");
	    } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.err.println("Error generating key pairs.");
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            System.err.println("Error writing digital signature.");
        } catch (SignatureException e) {
            e.printStackTrace();
            System.err.println("Error writing digital signature.");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            System.err.println("Error writing digital signature.");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            System.err.println("Error encrypting message.");
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            System.err.println("Error encrypting message.");
        } catch (BadPaddingException e) {
            e.printStackTrace();
            System.err.println("Error encrypting message.");
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            System.err.println("Error reading public key.");
        }
         
        // close the connection
        try {
            input.close();
            out.close();
            socket.close();
        } catch(IOException i) {
            System.out.println(i);
        }
    }

    public void generateKeyPairs() throws NoSuchAlgorithmException, FileNotFoundException, IOException, NoSuchProviderException {
        // Generate Keys
        // Key pair code found here: https://docs.oracle.com/javase/tutorial/security/apisign/step2.html
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(1024, random);

        KeyPair pair = keyGen.generateKeyPair();
        priv = pair.getPrivate();
        pub = pair.getPublic();

        /* save the public key in a file */
        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("pubKey1");
        keyfos.write(key);
        keyfos.close();
    }

    public byte[] encrypt(PublicKey publicKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  

        return cipher.doFinal(message.getBytes());  
    }

    public byte[] decrypt(PrivateKey key, String ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
        cipher.init(Cipher.DECRYPT_MODE, key);  
        return cipher.doFinal(ciphertext.getBytes());
    }

    public byte[] readFileBytes(String filename) throws IOException, FileNotFoundException {
        /*Path path = Paths.get(filename);
        return Files.readAllBytes(path);  */

        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();

        String str = new String(data, "UTF-8");

        return data;
    }

    public PublicKey readPublicKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(readFileBytes(filename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicSpec);       
    }
 
    public static void main(String[] args) {

        if (args.length != 2 ) {
            System.err.println("Error: Incorrect number of arguments. Program accepts 2 argumnets.");
            System.exit(0);
        }

        String address = args[0];
        int portNum = Integer.parseInt(args[1]);
        VoterCli client = new VoterCli(address, portNum);
    }
}
