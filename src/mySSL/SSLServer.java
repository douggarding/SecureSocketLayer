package mySSL;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SSLServer {

	private static int port = 8480;
	private static int sequenceNumber = 0;
	
	private static PublicKey serverPublicKey;
	private static PublicKey clientPublicKey;
	private static Certificate clientCertificate;
	private static Certificate serverCertificate;
	private static PrivateKey serverPrivateKey;
	private static byte[] serverNonce;
	private static byte[] clientNonce;
	private static byte[] masterKey;

	public static void main(String[] args) throws IOException, ClassNotFoundException, CertificateException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, SignatureException {

		serverPrivateKey = Handshake.getPrivateKey("serverKeys/serverPrivate.der"); // Get private key

		// Set up sockets and streams
		ServerSocket serverSocket = new ServerSocket(port);
		Socket clientSocket = serverSocket.accept(); // Blocks until a connection is made
		DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream()); // Read from
		DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream()); // Write to

		// ------------------- HANDSHAKE -------------------

		// Receive certificate, extract client's public key
		clientCertificate = Handshake.processCertificate(inputStream);
		clientPublicKey = clientCertificate.getPublicKey();
		System.out.println("<--- Server received client's certificate and public key.");

		// Send certificate
		serverCertificate = Handshake.sendCertificate("serverKeys/sslCertSigned.cert", outputStream);
		serverPublicKey = serverCertificate.getPublicKey();
		System.out.println("---> Server sent certificate to the client");

		// Create and send encrypted nonce
		serverNonce = Handshake.createAndSendNonce(outputStream, clientPublicKey);
		System.out.println("Server nonce: " + Arrays.toString(serverNonce));
		System.out.println("---> Server sent encrypted nonce to client.");

		// Receive client's nonce
		clientNonce = Handshake.receiveNonce(inputStream, serverPrivateKey);
		System.out.println("<--- Server received client's nonce.");
		System.out.println("Client nonce: " + Arrays.toString(clientNonce));

		// Generate master key
		masterKey = new byte[8];
		for (int i = 0; i < 8; i++) {
			masterKey[i] = (byte) (serverNonce[i] ^ clientNonce[i]);
		}

		// Send Handshake Confirmation MAC(allMessages, "SERVER")
		byte[] hMAC = Handshake.HMAC(clientPublicKey, serverPublicKey, clientNonce, serverNonce, "SERVER");
		Handshake.sendData(outputStream, hMAC);
		System.out.println("---> Server sent HMAC to client");

		// Receive HMAC from client and confirm
		boolean verified = Handshake.verifyIncomingHMAC(clientPublicKey, serverPublicKey, clientNonce, serverNonce,
				"CLIENT", inputStream);
		System.out.println("<--- Client received server's HMAC.");
		if (verified) {
			System.out.println("Client's HMAC was as expected");
		} else {
			System.out.println("Client's HMAC was NOT as expected");
		}

		
		// ------------------- SEND DATA -------------------
		
		
		// Create four sub-keys (Will be same on both sides when seeded with same master
		// key)
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(masterKey);
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
		keyGenerator.init(random);

		SecretKey serverEncKey = keyGenerator.generateKey(); // Session encryption for data sent from server to client
		SecretKey serverMACKey = keyGenerator.generateKey(); // Session MAC key for data sent from server to client
		SecretKey clientEncKey = keyGenerator.generateKey(); // Session encryption for data sent from client to server
		SecretKey clientMACKey = keyGenerator.generateKey(); // Session MAC key for data sent from client to server
		
		// Get the file to be transfered
		File file = new File("MobyDick.txt"); // data being sent
		byte[] fileBuffer = new byte[(int) file.length()]; // Create byte array for data
		FileInputStream fis = new FileInputStream(file); // Turn file into input stream
		fis.read(fileBuffer); // Put actual data from file into the byte array
		System.out.println("Data File Buffer Size: " + fileBuffer.length);;
		
		// Process data as segments no longer than 16384 bytes (16KB).
		for(int i = 0; i < fileBuffer.length; i+=16_384) {
			
			// Create data buffer for current segment. Will either be a full 16_384
			// byte array, or will be the length of however many bytes are remaining.
			byte[] dataBuffer;
			if(fileBuffer.length - i >= 16_384) {
				dataBuffer = Arrays.copyOfRange(fileBuffer, i, i + 16_384);
			}
			else {
				dataBuffer = Arrays.copyOfRange(fileBuffer, i, fileBuffer.length);
			}
			System.out.println("Data Buffer Size: " + dataBuffer.length);
			
			// Create a MAC of the data
			Mac mac = Mac.getInstance("HmacSHA1"); // Create the Mac object
			mac.init(serverMACKey); // Initialize the mac using the server's MAC key
			mac.update(Handshake.IntToByteArray(++sequenceNumber)); // Add the sequence number to the mac
			mac.update(dataBuffer); // Add the data to the mac
			byte[] dataHMAC = mac.doFinal(); // Create the mac
			System.out.println("Data HMAC Size: " + dataHMAC.length);
			
			// Create the data output cipher
			Cipher dataOutputCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			dataOutputCipher.init(Cipher.ENCRYPT_MODE, serverEncKey);
			// Encrypt the data + MAC
			dataOutputCipher.update(dataBuffer);
			dataOutputCipher.update(dataHMAC);
			byte[] encryptedData = dataOutputCipher.doFinal();
			
			System.out.println("Data Encrypted Size " + encryptedData.length + "\n");
		}
		
		// Send the data to the client 
		/*
		System.out.println("FILE BYTE ARRAY SIZE " + fileBuffer.length);
		outputStream.writeInt(fileBuffer.length); // Send length of DATA
		cipherOutputStream.write(fileBuffer);
		cipherOutputStream.flush();
		outputStream.writeInt(dataHMAC.length); // Send length of record HMAC
		cipherOutputStream.write(dataHMAC);
		
		*/
		System.out.println("Shutting down server");
	}

	

	

}
