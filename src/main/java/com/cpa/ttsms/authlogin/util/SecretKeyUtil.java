package com.cpa.ttsms.authlogin.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.cpa.ttsms.authlogin.service.AuthService;

@Component
public class SecretKeyUtil {

	@Autowired
	private AuthService authService;

	// Get secretKey using key id
	public String getSecretKey(int keyId) {
		return authService.getSecretKey(keyId);
	}

	// Get initialization vector using key id
	public String getInitVector(int keyId) {
		return authService.getInitVector(keyId);
	}

}
