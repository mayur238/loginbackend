package com.cpa.ttsms.authlogin.service;

import java.io.IOException;

import com.cpa.ttsms.authlogin.entity.AuthKey;
import com.cpa.ttsms.authlogin.entity.Password;

public interface AuthService {

	// Retrieves the server's public key for secure communication.
	Object getServerPublicKey() throws IOException;

	// Retrieves the server's random string
	AuthKey getServerRandomString();

	// Adds a client's random string to the AuthKey.
	AuthKey addClientRandomString(AuthKey authKey) throws Exception;

	// // Adds a client's pre-secret key to the AuthKey.
	AuthKey addClientPreSecretKey(AuthKey authKey) throws Exception;

	// Retrieves an AuthKey object by its unique keyId.
	AuthKey getAuthKeyByKeyId(int keyId);

	// Retrieves the secret key associated with a client's AuthKey.
	String getSecretKey(int keyId);

	String getInitVector(int keyId);

	public String processObject(Password password);

	AuthKey addInitilizationVector(AuthKey authKey);
}
