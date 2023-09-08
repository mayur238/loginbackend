package com.cpa.ttsms.authlogin.controller;

import java.util.Locale;
import java.util.ResourceBundle;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.cpa.ttsms.authlogin.dto.AuthRequest;
import com.cpa.ttsms.authlogin.dto.KeyDTO;
import com.cpa.ttsms.authlogin.entity.AuthKey;
import com.cpa.ttsms.authlogin.helper.ResponseHandler;
import com.cpa.ttsms.authlogin.service.AuthService;
import com.cpa.ttsms.authlogin.util.JwtUtil;
import com.cpa.ttsms.authlogin.util.JwtUtilWithoutUsernamePassword;

@RestController
@CrossOrigin
public class AuthController {

	@Autowired
	private AuthService authService;

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private JwtUtilWithoutUsernamePassword jwtUtilWIthoutUsernamePassword;

	@Autowired
	private AuthenticationManager authenticationManager;

	// The ResourceBundle is used to retrieve localized messages.
	private ResourceBundle resourceBundle;

	AuthController() {
		resourceBundle = ResourceBundle.getBundle("ErrorMessage", Locale.US);
	}

	@GetMapping("auth/serverpublickey")
	public ResponseEntity<Object> getServerPublicKey() {

		Object serverPublicKey = null;

		try {
			serverPublicKey = authService.getServerPublicKey();

			if (serverPublicKey != null) {

				return ResponseHandler.generateResponse(serverPublicKey, HttpStatus.OK);
			} else {
				return ResponseHandler.generateResponse(HttpStatus.NOT_FOUND, "err003");
			}
		} catch (Exception e) {
			e.printStackTrace();
			// Generate an INTERNAL_SERVER_ERROR response with an error message
			return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
		}

	}

	@GetMapping("auth/serverrandomstr")
	public ResponseEntity<Object> getServerRandomString() {

		AuthKey serverRandomString = null;

		try {
			serverRandomString = authService.getServerRandomString();

			System.out.println("serverRandomString : " + serverRandomString);
			if (serverRandomString != null) {
				return ResponseHandler.generateResponse(serverRandomString, HttpStatus.OK);
			} else {
				return ResponseHandler.generateResponse(HttpStatus.NOT_FOUND, "err003");
			}
		} catch (Exception e) {
			e.printStackTrace();
			// Generate an INTERNAL_SERVER_ERROR response with an error message
			return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
		}
	}

	@PostMapping("auth/clientrandomstr")
	public ResponseEntity<Object> addClientRandomString(@RequestBody AuthKey authKey) {

		AuthKey updatedAuthKey = null;

		try {
			updatedAuthKey = authService.addClientRandomString(authKey);

			if (updatedAuthKey != null) {
				return ResponseHandler.generateResponse(updatedAuthKey, HttpStatus.OK);
			} else {
				return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
			}
		} catch (Exception e) {
			e.printStackTrace();
			// Generate an INTERNAL_SERVER_ERROR response with an error message
			return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
		}
	}

	@PostMapping("auth/clientpresecretstr")
	public ResponseEntity<Object> addClientPreSecretKey(@RequestBody AuthKey authKey) {

		AuthKey updatedAuthKey = null;

		try {
			updatedAuthKey = authService.addClientPreSecretKey(authKey);

			if (updatedAuthKey != null) {
				return ResponseHandler.generateResponse(updatedAuthKey, HttpStatus.OK);
			} else {
				return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
			}
		} catch (Exception e) {
			e.printStackTrace();
			// Generate an INTERNAL_SERVER_ERROR response with an error message
			return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
		}
	}

	@PostMapping("auth/authenticate")
	public ResponseEntity<Object> generateToken(@RequestBody AuthRequest authRequest,
			@RequestParam("keyid") int keyId) {
		System.out.println("generateToken" + authRequest.toString());
		try {
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

			if (authentication.isAuthenticated()) {
				String generatedToken = null;
				generatedToken = jwtUtil.generateToken(authRequest.getUsername(), keyId);
				KeyDTO token = new KeyDTO(generatedToken);
				return ResponseHandler.generateResponse(token, HttpStatus.OK);

			} else {
				return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
			}

		} catch (Exception ex) {
			ex.printStackTrace();
			return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
		}

	}

	@PostMapping("auth/token/{keyid}")
	public ResponseEntity<Object> getToken(@PathVariable("keyid") int keyId) throws Exception {

		try {
			String generatedToken = null;
			generatedToken = jwtUtilWIthoutUsernamePassword.generateToken(keyId);

			KeyDTO token = new KeyDTO(generatedToken);
			return ResponseHandler.generateResponse(token, HttpStatus.OK);

		} catch (Exception e) {
			e.printStackTrace();
			// Generate an INTERNAL_SERVER_ERROR response with an error message
			return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
		}

	}

	@GetMapping("/hello")
	public ResponseEntity<Object> token() {
		System.out.println("hello");
		KeyDTO token = new KeyDTO("success");
		return ResponseHandler.generateResponse(token, HttpStatus.OK);
	}
}
