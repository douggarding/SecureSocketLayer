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

	private static int port = 8480;
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
		Cipher dataInputCipher = Cipher.getInstance("DESede/ECB/NoPadding");
		dataInputCipher.init(Cipher.DECRYPT_MODE, serverEncKey);
		CipherInputStream cipherInputStream = new CipherInputStream(inputStream, dataInputCipher);

		// READ DATA FROM THE SERVER
		int bytesRead = 0;
		int bytesToRead = inputStream.readInt();
		System.out.println("Number of data bytes: " + bytesToRead);
		byte[] dataBuffer = new byte[bytesToRead + (8 - bytesToRead % 8)]; // 6 added because cipher needs bytes by groups of 8
		// Read data bytes from the stream into the buffer
		while(bytesRead < bytesToRead) {
			bytesRead = inputStream.read(dataBuffer, bytesRead, bytesToRead - bytesRead);
		}
		
		// Decrypt the buffer full of data
		byte[] decrypted = dataInputCipher.doFinal(dataBuffer);

		System.out.println("Number of data bytes decrypted: " + decrypted.length);

		FileOutputStream ofs = new FileOutputStream("MobyDick3.txt");
		ofs.write(decrypted);
		
		int macLength = inputStream.readInt();
		System.out.println("MAC LENGTH: " + macLength);
		byte[] incomingRecordMac = new byte[macLength];
		cipherInputStream.read(incomingRecordMac);

		// Verify the MAC
		Mac mac = Mac.getInstance("HmacSHA1"); // Create the Mac object
		mac.init(serverMACKey); // Initialize the mac using the server's MAC key
		mac.update(Handshake.IntToByteArray(++sequenceNumber)); // Add the sequence number to the mac
		mac.update(dataBuffer); // Add the data to the mac
		byte[] secondRecordMac = mac.doFinal(); // Create the mac

		System.out.println(incomingRecordMac.length + " " + secondRecordMac.length);
		System.out.println(Arrays.equals(incomingRecordMac, secondRecordMac));
	}

}
