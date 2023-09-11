package com.cpa.ttsms.authlogin.service;

import java.security.PrivateKey;
import java.security.PublicKey;

/*
 * for RSA encryption and decryption services.
 * It provides methods to read RSA keys, decrypt data, and encrypt messages.
 */
public interface RSAService {

	// Reads the private key for RSA encryption/decryption.
	public PrivateKey readPrivateKey() throws Exception;

	// Reads the public key for RSA encryption/decryption.
	public PublicKey readPublicKey() throws Exception;

	// Decrypts encrypted data using the private key.
	public String decrypt(String encryptedData) throws Exception;

	// Encrypts a message using the public key.
	public String encrypt(String message) throws Exception;

}
