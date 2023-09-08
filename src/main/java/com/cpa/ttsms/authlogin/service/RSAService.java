package com.cpa.ttsms.authlogin.service;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface RSAService {

	public PrivateKey readPrivateKey() throws Exception;

	public PublicKey readPublicKey() throws Exception;

	public String decrypt(String encryptedData) throws Exception;

	public String encrypt(String message) throws Exception;

}
