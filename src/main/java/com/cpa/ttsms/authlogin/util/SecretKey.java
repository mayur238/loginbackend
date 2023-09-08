package com.cpa.ttsms.authlogin.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.cpa.ttsms.authlogin.entity.AuthKey;
import com.cpa.ttsms.authlogin.service.AuthService;
import com.cpa.ttsms.authlogin.service.RSAService;

@Component
public class SecretKey {

	@Autowired
	private AuthService authService;

	@Autowired
	private RSAService rsaService;

	public String getSecretKey(int keyId) {
//		AuthKey authKey = authService.getAuthKeyByKeyId(keyId);
		return authService.getSecretKey(keyId);
	}

	private String generateSecretKey(AuthKey authKey) {

		String key = null;
		try {
			key = rsaService.decrypt(authKey.getServerRandomString())
					+ rsaService.decrypt(authKey.getClientRandomString())
					+ rsaService.decrypt(authKey.getClientPreSecretKey());
			return key;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
}
