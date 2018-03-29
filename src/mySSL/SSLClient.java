/*
 * .pem - generic public and private keys
 * .der - java understandable public and private keys 
 * 
 */

package mySSL;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;

public class SSLClient {
	
	private static PublicKey clientPublicKey;
	private static PublicKey serverPublicKey;
	private static Certificate clientCert;
	private static Certificate serverCert;

	public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException, CertificateException {

		// Establish connection with the server
		InetAddress host = InetAddress.getLocalHost();
		int port = 8486;
		Socket clientSocket = new Socket(host.getHostName(), port);
		DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream()); // Read from this
		DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream()); // Write to this
		
		// ------------------- HANDSHAKE -------------------
		
		// Send CERT{K+}, 
		System.out.println("HANDSHAKE: CERT{K+}");
		CertificateFactory certFactory = CertificateFactory.getInstance ("X.509"); // Certificate factory
		FileInputStream certFileInputStream = new FileInputStream("clientKeys/sslCertSigned.cert"); // To read certificate
		clientCert = certFactory.generateCertificate (certFileInputStream); // Get client's certificate
		System.out.println (clientCert.toString());

		clientPublicKey = clientCert.getPublicKey(); // Collect the client's public key
		outputStream.write(clientCert.getEncoded()); // Send the certificate to the server
		outputStream.flush();
		
		
		// Receive CERT-{K+}, KEY-{NONCE1}
		
		// Send KEY-{NONCE2}
		
		// Generate master secret (MS) NONCE1 xor NONCE2
		
		// Send Handshake Confirmation MAC(allMessages, CLIENT)
		
		// Receive Handshake, verify
		
		
		
		
		
		/*
		// Set up streams with the socket
		PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
		BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		// Set up stream with the console input
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

		String userInput;
		while ((userInput = stdIn.readLine()) != null) {
		    out.println(userInput);
		    System.out.println("echo: " + in.readLine());
		}
		*/
	}

}
