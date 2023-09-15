package com.cpa.ttsms.authlogin.service;

import javax.crypto.SecretKey;

public interface AESService {

	// Decrypts encrypted data
	public String decrypt(String encryptedData, int keyId) throws Exception;

	// Encrypts a message
	public String encrypt(String message, int keyId) throws Exception;

	public SecretKey getKey(int keyId);
}
