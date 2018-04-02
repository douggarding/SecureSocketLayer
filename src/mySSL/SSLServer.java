package mySSL;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class SSLServer {

	private static int port = 8490;
	private static PublicKey clientPublicKey;
	private static PublicKey serverPublicKey;
	private static PrivateKey serverPrivateKey;
	private static Certificate clientCert;
	private static Certificate serverCert;

	public static void main(String[] args) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {

		// Set up sockets and streams
		ServerSocket serverSocket = new ServerSocket(port);
		Socket clientSocket = serverSocket.accept(); // Blocks until a connection is made
		DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream()); // Read from
		DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream()); // Write to

		// Receive CERT{CK+}, extract client's public key
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509"); // Certificate factory	
		clientCert = certFactory.generateCertificate(inputStream); // Get client's certificate
		System.out.println("SERVER PRINTING CERTIFICATE: \n" + clientCert.toString()); // Print certificate for testing
		clientPublicKey = clientCert.getPublicKey();
		
		// Send CERT{SK+}
		FileInputStream certFileInputStream = new FileInputStream("serverKeys/sslCertSigned.cert"); // To read certificate
		serverCert = certFactory.generateCertificate(certFileInputStream);
		serverPublicKey = serverCert.getPublicKey();
		outputStream.write(serverCert.getEncoded()); // Send the certificate to the server
		outputStream.flush();
		
		// Get private key
		FileInputStream certPrivateKeyIS = new FileInputStream("serverKeys/sslCertSigned.cert");
		int inputSize = certPrivateKeyIS.available();
		byte[] keyInput = new byte[inputSize];
		certPrivateKeyIS.read(keyInput);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInput);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		serverPrivateKey = keyFactory.generatePrivate(keySpec);
		
		
		System.out.println("Shutting down server");

	}

}
