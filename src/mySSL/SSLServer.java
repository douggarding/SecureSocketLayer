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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SSLServer {

	private static int port = 8492;
	private static PublicKey clientPublicKey;
	private static PrivateKey serverPrivateKey;
	private static Certificate clientCert;
	private static Certificate serverCert;
	private static long serverNonce;

	public static void main(String[] args) throws IOException, ClassNotFoundException, CertificateException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		getPrivateKey(); // Get private key
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509"); // Certificate factory

		// Set up sockets and streams
		ServerSocket serverSocket = new ServerSocket(port);
		Socket clientSocket = serverSocket.accept(); // Blocks until a connection is made
		DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream()); // Read from
		DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream()); // Write to

		// Receive CERT{CK+}, extract client's public key
		recieveClientCert(inputStream, certFactory);

		// Send CERT{SK+}
		sendServerCert(outputStream, certFactory);

		// Send encrypted nonce
		// Create nonce
		SecureRandom random = new SecureRandom();
		byte serverNonce[] = new byte[8];
		random.nextBytes(serverNonce);
		System.out.println("Server's nonce, first byte: " + serverNonce[0]);
		// encrypt nonce
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(cipher.ENCRYPT_MODE, clientPublicKey);
		byte[] encryptedNonce = cipher.doFinal(serverNonce);
		System.out.println("Server's encrypted nonce, first byte: " + encryptedNonce[0]);
		outputStream.write(encryptedNonce);
		outputStream.flush();
		System.out.println("Server sent encrypted nonce to client.");
		
		System.out.println("Shutting down server");
	}

	/**
	 * Private helper method for turning a byte array of 8 bytes into
	 * a long. Intended nonce conversion
	 * .
	 * @param a byte array of 8 bytes
	 * @return long of thne byte array supplied
	 */
	private static long bytesToLong(byte[] bytes) {
		assert(bytes.length == 8);
		
        long nonce = 0;
        for (int i = 0; i < bytes.length; i++) {
            nonce = nonce << 8;
            nonce = nonce | bytes[i];
        }

        return nonce;
	}
	

	/**
	 * Sends the server's certificate to the client
	 * 
	 * @param outputStream
	 * @param certFactory
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws CertificateEncodingException
	 */
	private static void sendServerCert(DataOutputStream outputStream, CertificateFactory certFactory)
			throws FileNotFoundException, CertificateException, IOException, CertificateEncodingException {
		System.out.println("Server sending certificate to client.");
		FileInputStream certFileInputStream = new FileInputStream("serverKeys/sslCertSigned.cert");
		serverCert = certFactory.generateCertificate(certFileInputStream);
		outputStream.write(serverCert.getEncoded()); // Send the certificate to the server
		outputStream.flush();
		System.out.println("Server sent certificate to client.");
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
	private static void recieveClientCert(DataInputStream inputStream, CertificateFactory certFactory)
			throws CertificateException, NoSuchAlgorithmException {
		System.out.println("Server start recieving certificate from client.");
		clientCert = certFactory.generateCertificate(inputStream); // Get client's certificate
		System.out.println("Server recieved client certificate.");
		clientPublicKey = clientCert.getPublicKey();
		System.out.println("Server extracted client's public key.");

		System.out.println("Server started verifying client's certificate with their public key.");
		// Verify the certificate with client's public key
		try {
			clientCert.verify(clientPublicKey);
			System.out.println("Server verified client's certificate with their public key.");
		} catch (InvalidKeyException | NoSuchProviderException | SignatureException e) {
			System.out.println("Failed to verify the clients certificate with their public key");
			e.printStackTrace();
		}

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
		FileInputStream certPrivateKeyIS = new FileInputStream("serverKeys/serverPrivate.der");
		int inputSize = certPrivateKeyIS.available();
		byte[] keyInput = new byte[inputSize];
		certPrivateKeyIS.read(keyInput);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInput);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		serverPrivateKey = keyFactory.generatePrivate(keySpec);
	}

}
