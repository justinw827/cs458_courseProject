import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.security.spec.*;
import java.security.*;
import java.io.*;

public class Vf {

	//initialize socket and input stream
    private Socket          socket   = null;
    private ServerSocket    server   = null;

    private PrivateKey priv;
    private PublicKey pub;
 
    // constructor with port
    public Vf(int port) {
        // starts server and waits for a connection
        try {
            // Create a SSL Server Socket Factory
            SSLServerSocketFactory sslServerSocketFactory = 
                (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();

            // Create a SSL Server Socket with SSL Socket Factory 
            server = sslServerSocketFactory.createServerSocket(port);
            System.out.println("SSL Server started");
 
            System.out.println("Waiting for a client ...");
 
            socket = server.accept();
            System.out.println("Client accepted");
 
            // out.println("string") sends a string over the socket
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            try { 

                // Generate Public and Private Key for Voter Server
                generateKeyPairs();

           /*     // Write Public Key to file named serverPubKey.der
                byte[] key = pub.getEncoded();
                FileOutputStream keyfos = new FileOutputStream("serverPubKey.der");
                keyfos.write(key);
                keyfos.close();*/

                // Buffered reader for socket input
                BufferedReader br = 
                    new BufferedReader(
                            new InputStreamReader(socket.getInputStream()));

                String line = br.readLine();

                // Decrypt line

                String message = decrypt(priv, line).toString();
                
                String[] tokens = message.split(":");
                String name = tokens[0]; // Get username
                String vNumber = tokens[1]; // Get password
                String dSig = tokens[2]; // Get digital signature

                System.out.println("Name: " + name);
                System.out.println("vNumber: " + vNumber);
                System.out.println("dSig: " + dSig);


/*
                // Open file with name "password.txt"
                File file = new File("password.txt");
                FileReader fr;
                BufferedReader brFile; // Buffered reader for file

                // Password file format
                // <user ID> <hashed password> <date and time when the password is stored>
                String idCheck = "";
                String fileLine = "";
                String storedPW = "";
                String date = ""; // Date and time
                try {
                    fr = new FileReader(file);
                    brFile = new BufferedReader(fr);
                     // Look for matching username in password file
                    while (idCheck != username && fileLine != null) {
                        fileLine = brFile.readLine();
                        String[] tokens2 = fileLine.split(" ");
                        storedPW = tokens2[1]; // Store password
                        date = tokens2[2]; // Store date and time
                        idCheck = tokens2[0];
                    }
                } catch (FileNotFoundException e) {
                    System.err.println("Error opening file.");
                    e.printStackTrace();
                }

                // Hash password with MD5
                String hashtext = hashMD5(password);

                System.out.println(hashtext);

                if (idCheck == username) {
                    if (hashtext == storedPW) {
                        out.println("OK");
                    } else {
                        out.println("Incorrect");
                    }
                }*/

            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Error while reading from socket.");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                System.err.println("Error generating key pairs.");
            } catch (InvalidKeyException e) {
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
            }

            System.out.println("Closing connection");
 
            // close connection
            socket.close();
        } catch(IOException e) {
            e.printStackTrace();
            System.err.println("Error using socket.");
        }
    }

    private String hashMD5(String textIn) {
        // Hash password from client
        String hashtext = "";
        try {
            String plaintext = textIn;
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.reset();
            m.update(plaintext.getBytes());
            byte[] digest = m.digest();
            BigInteger bigInt = new BigInteger(1,digest);
            hashtext = bigInt.toString(16); // Hashed password as string
            // Now we need to zero pad it if you actually want the full 32 chars.
            while (hashtext.length() < 32 ) {
                hashtext = "0"+hashtext;
            }
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error running MD5.");
            e.printStackTrace();
        }

        return hashtext;
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
        FileOutputStream keyfos = new FileOutputStream("serverPubKey.der");
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
 
    public static void main(String[] args) {

    	if (args.length != 1 ) {
			System.err.println("Error: Incorrect number of arguments. Program accepts 1 argumnet.");
			System.exit(0);
		}

		int portNum = Integer.parseInt(args[0]);

        Vf server = new Vf(portNum);
    }
}
