/*
 * .pem - generic public and private keys
 * .der - java understandable public and private keys 
 * 
 */

package mySSL;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.cert.Certificate;

public class SSLClient {

	private static int port = 8485;
	private static int sequenceNumber = 0;

	// Handshake variables
	private static PublicKey serverPublicKey;
	private static PublicKey clientPublicKey;
	private static Certificate clientCertificate;
	private static Certificate serverCertificate;
	private static PrivateKey clientPrivateKey;
	private static byte[] serverNonce;
	private static byte[] clientNonce;
	private static byte[] masterKey;

	// Data transfer variables
	private static SecretKey serverEncKey;
	private static SecretKey serverMACKey;
	private static SecretKey clientEncKey;
	private static SecretKey clientMACKey;

	public static void main(String[] args)
			throws IOException, ClassNotFoundException, InterruptedException, CertificateException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, SignatureException {

		clientPrivateKey = Handshake.getPrivateKey("clientKeys/clientPrivate.der");

		// Establish connection with the server
		InetAddress host = InetAddress.getLocalHost();
		Socket clientSocket = new Socket(host.getHostName(), port);
		DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream()); // Read from this
		DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream()); // Write to this

		// ------------------- HANDSHAKE -------------------

		// Send Certificate
		clientCertificate = Handshake.sendCertificate("clientKeys/sslCertSigned.cert", outputStream);
		clientPublicKey = clientCertificate.getPublicKey();
		System.out.println("---> Client sent certificate to Server.");

		// Receive Certificate and extract server's public key
		serverCertificate = Handshake.processCertificate(inputStream);
		serverPublicKey = serverCertificate.getPublicKey();
		System.out.println("<--- Client received server's certificate and public key.");

		// Receive and decrypt server's Nonce
		serverNonce = Handshake.receiveNonce(inputStream, clientPrivateKey);
		System.out.println("<--- Client received server's nonce.");
		System.out.println("Server nonce: " + Arrays.toString(serverNonce));

		// Send nonce
		clientNonce = Handshake.createAndSendNonce(outputStream, serverPublicKey);
		System.out.println("Client nonce: " + Arrays.toString(clientNonce));
		System.out.println("---> Client sent encrypted nonce to server.");

		// Generate master secret key
		masterKey = new byte[8];
		for (int i = 0; i < 8; i++) {
			masterKey[i] = (byte) (serverNonce[i] ^ clientNonce[i]);
		}

		// Receive HMAC from server and confirm
		boolean verified = Handshake.verifyIncomingHMAC(clientPublicKey, serverPublicKey, clientNonce, serverNonce,
				"SERVER", inputStream);
		System.out.println("<--- Client received server's HMAC.");
		if (verified) {
			System.out.println("Server's HMAC was as expected");
		} else {
			System.out.println("Server's HMAC was NOT as expected");
		}

		// Send Handshake Confirmation MAC(allMessages, CLIENT)
		byte[] hMAC = Handshake.HMAC(clientPublicKey, serverPublicKey, clientNonce, serverNonce, "CLIENT");
		Handshake.sendData(outputStream, hMAC);
		System.out.println("---> Client sent HMAC to server");

		// ------------------- RECEIVE DATA -------------------

		// Create four sub-keys (Will be same on both sides when seeded with same master
		// key)
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(masterKey);
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
		keyGenerator.init(random);

		serverEncKey = keyGenerator.generateKey(); // Session encryption for data sent from server to client
		serverMACKey = keyGenerator.generateKey(); // Session MAC key for data sent from server to client
		clientEncKey = keyGenerator.generateKey(); // Session encryption for data sent from client to server
		clientMACKey = keyGenerator.generateKey(); // Session MAC key for data sent from client to server

		// Create the data input cipher and stream
		Cipher decryptionCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		decryptionCipher.init(Cipher.DECRYPT_MODE, serverEncKey);

		byte[] data;
		FileOutputStream fileOutputStream = new FileOutputStream("MobyDick3.txt");
		
		while(inputStream.available() > 0) {
			
			// READ DATA FROM THE SERVER
			int bytesRead = 0;
			int bytesToRead = inputStream.readInt();
			System.out.println("Number of bytes to read: " + bytesToRead);
			byte[] dataBuffer = new byte[bytesToRead];
			// Read data bytes from the stream into the buffer
			while(bytesRead < bytesToRead) {
				bytesRead = inputStream.read(dataBuffer, bytesRead, bytesToRead - bytesRead);
			}
			
			// Decrypt Data
			System.out.println("Number of bytes in encrypted data: " + dataBuffer.length);
			byte[] decrypted = decryptionCipher.doFinal(dataBuffer);
			System.out.println("Number of bytes in decrypted data: " + decrypted.length);
			
			// Separate MAC and data
			byte[] receivedData = Arrays.copyOfRange(decrypted, 0, decrypted.length - 20);
			byte[] receivedMac = Arrays.copyOfRange(decrypted, decrypted.length - 20, decrypted.length);
			System.out.println("Received Data Size: " + receivedData.length);
			System.out.println("Received Mac Size: " + receivedMac.length);
			
			// Compute expected HMAC
			Mac mac = Mac.getInstance("HmacSHA1"); // Create the Mac object
			mac.init(serverMACKey); // Initialize the mac using the server's MAC key
			mac.update(Handshake.IntToByteArray(++sequenceNumber)); // Add the sequence number to the mac
			mac.update(receivedData); // Add the data to the mac
			byte[] expectedMac = mac.doFinal(); // Create the mac
			
			// Verify the received and expected MACs
			System.out.println("Received HMAC: " + Arrays.toString(receivedMac));
			System.out.println("Expected HMAC: " + Arrays.toString(expectedMac));
			
			boolean areMacsEqual = Arrays.equals(receivedMac, expectedMac);
			if(areMacsEqual)
				System.out.println("HMAC's were equal, data integrity confirmed.");
			else
				System.out.println("HMAC's were not equal, data integrity check failed.");
			
			// Write data to file
			fileOutputStream.write(receivedData);
		}

		
		fileOutputStream.flush();
		fileOutputStream.close();
		
	}

}
