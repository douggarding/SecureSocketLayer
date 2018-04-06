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
import java.net.UnknownHostException;
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

	private static int sequenceNumber = 0;
	private static Socket clientSocket;
	public static int port = 8485;

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

	public static void main(String[] args) {

		// ------------------- CONNECTION TO SERVER -------------------

		InetAddress host;
		DataInputStream inputStream; // Read from this
		DataOutputStream outputStream; // Write to this

		try {
			host = InetAddress.getLocalHost();
			clientSocket = new Socket(host.getHostName(), port);
			inputStream = new DataInputStream(clientSocket.getInputStream());
			outputStream = new DataOutputStream(clientSocket.getOutputStream());
		} catch (IOException e) {
			System.out.println("Failed to connect to the server.");
			e.printStackTrace();
			return;
		}

		// ------------------- HANDSHAKE -------------------

		// Generate the client's private key from pre-established file.
		try {
			clientPrivateKey = Handshake.getPrivateKey("clientKeys/clientPrivate.der");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			System.out.println("Failed to generate client's private Key. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Send Certificate
		try {
			clientCertificate = Handshake.sendCertificate("clientKeys/sslCertSigned.cert", outputStream);
			clientPublicKey = clientCertificate.getPublicKey();
			System.out.println("---> Client sent certificate to Server.");
		} catch (CertificateException | IOException e) {
			System.out.println("Failed to generate client's or send client's certificate. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Receive Certificate and extract server's public key
		try {
			serverCertificate = Handshake.processCertificate(inputStream);
			serverPublicKey = serverCertificate.getPublicKey();
			System.out.println("<--- Client received server's certificate and public key.");
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			System.out.println("Failed to receive server's certificate. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Receive and decrypt server's Nonce
		try {
			serverNonce = Handshake.receiveNonce(inputStream, clientPrivateKey);
			System.out.println("<--- Client received server's nonce.");
			System.out.println("Server nonce: " + Arrays.toString(serverNonce));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			System.out.println("Failed to receive or process server's nonce. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Send nonce
		try {
			clientNonce = Handshake.createAndSendNonce(outputStream, serverPublicKey);
			System.out.println("Client nonce: " + Arrays.toString(clientNonce));
			System.out.println("---> Client sent encrypted nonce to server.");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			System.out.println("Failed to create or send nonce to server. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Generate master secret key
		masterKey = new byte[8];
		for (int i = 0; i < 8; i++) {
			masterKey[i] = (byte) (serverNonce[i] ^ clientNonce[i]);
		}

		// Receive and verify HMAC from server
		try {
			boolean verified = Handshake.verifyIncomingHMAC(clientPublicKey, serverPublicKey, clientNonce, serverNonce,
					"SERVER", inputStream);

			System.out.println("<--- Client received server's HMAC.");
			if (verified) {
				System.out.println("Server's handshake HMAC was as expected");
			} else {
				System.out.println("Server's handshake HMAC was NOT as expected. Disconnecting from server.");
				disconnectFromServer();
				return;
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			System.out.println("Failed to receive or process HMAC from server. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Send Handshake Confirmation MAC(allMessages, CLIENT)
		byte[] hMAC;
		try {
			hMAC = Handshake.HMAC(clientPublicKey, serverPublicKey, clientNonce, serverNonce, "CLIENT");
			Handshake.sendData(outputStream, hMAC);
			System.out.println("---> Client sent HMAC to server");
		} catch (NoSuchAlgorithmException | IOException e) {
			System.out.println("Failed to generate or send HMAC to server. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// ------------------- RECEIVE DATA -------------------

		// Create four sub-keys (Will be same on both sides when seeded with same master
		// key)
		SecureRandom random;
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(masterKey);
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			keyGenerator.init(random);

			serverEncKey = keyGenerator.generateKey(); // Session encryption for data sent from server to client
			serverMACKey = keyGenerator.generateKey(); // Session MAC key for data sent from server to client
			clientEncKey = keyGenerator.generateKey(); // Session encryption for data sent from client to server
			clientMACKey = keyGenerator.generateKey(); // Session MAC key for data sent from client to server

		} catch (NoSuchAlgorithmException e) {
			System.out.println("Failed to set up and generate data transfer keys. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Create the data input cipher and stream
		Cipher decryptionCipher;
		try {
			decryptionCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			decryptionCipher.init(Cipher.DECRYPT_MODE, serverEncKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			System.out.println("Failed to set up decryption ciphet. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Create output stream for writing incoming data to file
		byte[] data;
		FileOutputStream fileOutputStream;
		try {
			fileOutputStream = new FileOutputStream("MobyDick3.txt");
		} catch (FileNotFoundException e) {
			System.out.println("Failed to create output stream for writing file. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}

		// Loop for collecting and processing data from the server
		try {
			while (inputStream.available() > 0) {

				// READ DATA FROM THE SERVER
				int bytesRead = 0;
				int bytesToRead = inputStream.readInt();
				System.out.println("Number of bytes to read: " + bytesToRead);
				byte[] dataBuffer = new byte[bytesToRead];
				// Read data bytes from the stream into the buffer
				while (bytesRead < bytesToRead) {
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
				if (areMacsEqual)
					System.out.println("HMAC's were equal, data integrity confirmed.");
				else
					System.out.println("HMAC's were not equal, data integrity check failed.");

				// Write data to file
				fileOutputStream.write(receivedData);
			}
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| IllegalStateException | IOException e) {
			System.out.println(
					"Failed to receive data from server, process data, or write data to a file. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			try {
				fileOutputStream.close();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			return;
		}

		try {
			fileOutputStream.flush();
			fileOutputStream.close();
		} catch (IOException e) {
			System.out.println("Failed to close file output stream. Disconnecting from server.");
			e.printStackTrace();
			disconnectFromServer();
			return;
		}
		

		// CLOSE THE CONNECTION SOCKET
		disconnectFromServer();

	}

	/**
	 * Private helper method that simply closes the connection with the server.
	 */
	private static void disconnectFromServer() {
		try {
			clientSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
