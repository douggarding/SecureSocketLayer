package mySSL;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class SSLServer {

	private static int port = 8486;
	private static PublicKey clientPublicKey;
	private static PublicKey serverPublicKey;
	private static Certificate clientCert;
	private static Certificate serverCert;
	
	public static void main(String[] args) throws IOException, ClassNotFoundException, CertificateException {
	         
		// Set up sockets and streams
		ServerSocket serverSocket = new ServerSocket(port);
		while(true) {
			Socket clientSocket = serverSocket.accept();
			DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream()); // Read from
			DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream()); // Write to
			
			// Receive CERT{K+},
			CertificateFactory certFactory = CertificateFactory.getInstance ("X.509"); // Certificate factory
			while(inputStream.available() > 0) {
				clientCert = certFactory.generateCertificate (inputStream); // Get client's certificate
				System.out.println (clientCert.toString());
			}
			
		}
		
		
		
		//System.out.println("Shutting down server");

	}

}
