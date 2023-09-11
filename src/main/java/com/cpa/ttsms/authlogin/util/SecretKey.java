package com.cpa.ttsms.authlogin.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.cpa.ttsms.authlogin.service.AuthService;

@Component
public class SecretKey {

	@Autowired
	private AuthService authService;

	// Get secretKey using key id
	public String getSecretKey(int keyId) {
		return authService.getSecretKey(keyId);
	}
}
