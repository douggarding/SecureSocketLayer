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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.cert.Certificate;

public class SSLClient {

	private static PublicKey serverPublicKey;
	private static PrivateKey clientPrivateKey;
	private static Certificate clientCert;
	private static Certificate serverCert;

	public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException,
			CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509"); // Certificate factory
		getPrivateKey();
		
		// Establish connection with the server
		InetAddress host = InetAddress.getLocalHost();
		int port = 8492;
		Socket clientSocket = new Socket(host.getHostName(), port);
		DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream()); // Read from this
		DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream()); // Write to this

		// ------------------- HANDSHAKE -------------------

		// Send CERT{CK+},
		System.out.println("Client sending certificate to Server.");
		FileInputStream certFileInputStream = new FileInputStream("clientKeys/sslCertSigned.cert"); // To read																							// certificate
		clientCert = certFactory.generateCertificate(certFileInputStream); // Get client's certificate
		outputStream.write(clientCert.getEncoded()); // Send the certificate to the server
		outputStream.flush();
		System.out.println("Client sent certificate to Server.");

		// Receive CERT{SK+} 
		receiveClientCert(inputStream, certFactory);
		
		// Receive S-KEY{S-NONCE}
		System.out.println("Client start recieving nonce from server.");
		byte[] serverEncryptedNonce = new byte[8];
		inputStream.read(serverEncryptedNonce); // Get client's certificate
		System.out.println("Client recieved server's encrypted nonce, first byte: " + serverEncryptedNonce[0]);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(cipher.DECRYPT_MODE, clientPrivateKey);
		byte[] serverNonce = cipher.doFinal(serverEncryptedNonce);

		System.out.println("Client decrypted server's encrypted nonce: " + serverNonce);

		// Send KEY-{C-NONCE}

		// Generate master secret (MS) NONCE1 xor NONCE2

		// Send Handshake Confirmation MAC(allMessages, CLIENT)

		// Receive Handshake, verify


	}

	/**
	 * Extracts the servers private key from the supplied private key file.
	 * 
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static void getPrivateKey()
			throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		FileInputStream certPrivateKeyIS = new FileInputStream("clientKeys/clientPrivate.der");
		int inputSize = certPrivateKeyIS.available();
		byte[] keyInput = new byte[inputSize];
		certPrivateKeyIS.read(keyInput);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInput);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		clientPrivateKey = keyFactory.generatePrivate(keySpec);
	}

	/**
	 * Pulls the incoming client certificate out of the inputStream. Extracts the
	 * client's public key from the certificate and then verifies the certificate
	 * with the key.
	 * 
	 * @param inputStream
	 * @return
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 */
	private static void receiveClientCert(DataInputStream inputStream, CertificateFactory certFactory)
			throws CertificateException, NoSuchAlgorithmException {
		System.out.println("Client start recieving certificate from server.");
		serverCert = certFactory.generateCertificate(inputStream); // Get client's certificate
		System.out.println("Client recieved server certificate.");
		serverPublicKey = serverCert.getPublicKey();
		System.out.println("Client extracted server's public key.");

		System.out.println("Client started verifying server's certificate with their public key.");
		// Verify the certificate with client's public key
		try {
			serverCert.verify(serverPublicKey);
			System.out.println("Client verified server's certificate with their public key.");
		} catch (InvalidKeyException | NoSuchProviderException | SignatureException e) {
			System.out.println("Failed to verify the servers certificate with their public key");
			e.printStackTrace();
		}

	}
	
}
