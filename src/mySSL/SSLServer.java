package mySSL;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SSLServer {

	private static int port = 8492;
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
		
		
		

		System.out.println("Shutting down server");
	}

	/**
	 * Private helper method for turning a byte array of 8 bytes into a long.
	 * Intended nonce conversion .
	 * 
	 * @param a
	 *            byte array of 8 bytes
	 * @return long of thne byte array supplied
	 */
	private static long bytesToLong(byte[] bytes) {
		assert (bytes.length == 8);

		long nonce = 0;
		for (int i = 0; i < bytes.length; i++) {
			nonce = nonce << 8;
			nonce = nonce | bytes[i];
		}

		return nonce;
	}

}
