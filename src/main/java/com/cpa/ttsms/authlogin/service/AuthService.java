package com.cpa.ttsms.authlogin.service;

import java.io.IOException;

import com.cpa.ttsms.authlogin.entity.AuthKey;

public interface AuthService {

	Object getServerPublicKey() throws IOException;

	AuthKey getServerRandomString();

	AuthKey addClientRandomString(AuthKey authKey) throws Exception;

	AuthKey addClientPreSecretKey(AuthKey authKey) throws Exception;

	AuthKey getAuthKeyByKeyId(int keyId);

	String getSecretKey(int keyId);
}
