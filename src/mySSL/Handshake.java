package mySSL;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Handshake {

	/**
	 * Extracts the servers private key from the supplied private key file.
	 * 
	 * @param keyPath
	 *            The file path where they key's .der file can be located.
	 * @return - PrivateKey object representing the private key contained in the
	 *         file.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	static PrivateKey getPrivateKey(String keyPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		// Grab data out of key file and put into a byte array
		FileInputStream keyInputStream = new FileInputStream(keyPath);
		int inputSize = keyInputStream.available();
		byte[] keyInput = new byte[inputSize];
		keyInputStream.read(keyInput);

		// Generate and return the PrivateKey object
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInput);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}

	
	/**
	 * Takes the filepath to a certificate and writes it to a DataOutputStream
	 * 
	 * @param certificatePath File location of the certificate
	 * @param outputStream Stream to which the certificate will be written
	 * @return 
	 * @throws CertificateException
	 * @throws IOException
	 */
	static Certificate sendCertificate(String certificatePath, DataOutputStream outputStream) throws CertificateException, IOException {
		
		// Generate a Certificate from the supplied file
		FileInputStream certFileInputStream = new FileInputStream(certificatePath); 
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		Certificate certificate = certFactory.generateCertificate(certFileInputStream);
		
		// Send the Certificate through the outputStream
		outputStream.write(certificate.getEncoded()); // Send the certificate to the server
		outputStream.flush();
		
		return certificate;
	}
	
	
	/**
	 * Pulls the incoming client certificate out of the inputStream. Extracts the
	 * client's public key from the certificate and then verifies the certificate
	 * with the key.
	 * 
	 * @param inputStream
	 * @return - PublicKey object extracted from the certificate
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws InvalidKeyException 
	 */
	static Certificate processCertificate(DataInputStream inputStream)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
		
		// Get client's certificate
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		Certificate certificate = certFactory.generateCertificate(inputStream); 
		
		// Extract and verify public key associated with the certificate
		PublicKey publicKey = certificate.getPublicKey();
		certificate.verify(publicKey);
		
		return certificate;

	}

	/**
	 * Generates a random 8 byte nonce. Encrypts the nonce using the provided public key, and writes
	 * the encrypted nonce to the provided output stream.
	 * 
	 * @param outputStream - Stream to which the encrypted nonce will be written.
	 * @param publicKey - Public key belonging to whomever this nonce is being sent. The public
	 * key is used to encrypt the nonce.
	 * @return Eight byte array representing a randomly generated nonce
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	static byte[] createAndSendNonce(DataOutputStream outputStream, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		// Generate nonce
		SecureRandom random = new SecureRandom();
		byte[] nonce = new byte[8];
		random.nextBytes(nonce);
		
		// Encrypt nonce
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedNonce = cipher.doFinal(nonce);

		// Send nonce
		outputStream.writeInt(encryptedNonce.length);
		outputStream.write(encryptedNonce);
		outputStream.flush();
		
		return nonce;
	}


	/**
	 * Reads the encrypted nonce being sent on the input stream. Decryptes the nonce
	 * and returns it as a 8-byte byte array. 
	 * 
	 * @param inputStream - Stream from which the encrypted nonce is read
	 * @param privateKey - Key required to decrypt the nonce.
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	static byte[] receiveNonce(DataInputStream inputStream, PrivateKey privateKey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		// Read encrypted nonce from input stream
		int nonceSize = inputStream.readInt();
		byte[] serverEncryptedNonce = new byte[nonceSize];
		inputStream.read(serverEncryptedNonce);
		
		// Decrypt and return nonce
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(cipher.DECRYPT_MODE, privateKey);
		byte[] nonce = cipher.doFinal(serverEncryptedNonce);
		return nonce;
	}

}
