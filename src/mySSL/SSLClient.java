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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.cert.Certificate;

public class SSLClient {

	private static int port = 8492;
	private static PublicKey serverPublicKey;
	private static PublicKey clientPublicKey;
	private static Certificate clientCertificate;
	private static Certificate serverCertificate;
	private static PrivateKey clientPrivateKey;
	private static byte[] serverNonce;
	private static byte[] clientNonce;
	private static byte[] masterKey;

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

		// Create four sub-keys
		// Look into CipherOutputStream for sending messages
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(masterKey); // s is the master secret

		KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
		keyGenerator.init(random);

		SecretKey clientAuthKey = keyGenerator.generateKey();
		SecretKey serverAuthKey = keyGenerator.generateKey();
		SecretKey clientEncKey = keyGenerator.generateKey();
		SecretKey serverEncKey = keyGenerator.generateKey();
		
	}

}
