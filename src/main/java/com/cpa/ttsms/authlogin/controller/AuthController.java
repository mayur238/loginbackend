package com.cpa.ttsms.authlogin.controller;

import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;
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
import com.cpa.ttsms.authlogin.exception.CPException;
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

	// The logger is used for logging messages related to this class.
	private static Logger LOGGER;

	AuthController() {
		resourceBundle = ResourceBundle.getBundle("ErrorMessage", Locale.US);
		LOGGER = Logger.getLogger(AuthController.class);
	}

	/*
	 * @Description : Handles HTTP GET request for auth/serverpublickey api
	 * 
	 * @Response : server's public key
	 */
	@GetMapping("auth/serverpublickey")
	public ResponseEntity<Object> getServerPublicKey() throws CPException {

		LOGGER.info("Getting server public key");
		// Variable to store server's public key
		Object serverPublicKey = null;

		try {
			// Call to AuthService to retrieve the server's public key
			serverPublicKey = authService.getServerPublicKey();

			// Check server's public key successfully retrieved
			if (serverPublicKey != null) {
				LOGGER.info("server public key generate successfuly");
				// If key exist then generate response with status
				return ResponseHandler.generateResponse(serverPublicKey, HttpStatus.OK);
			} else {
				LOGGER.error("Failed to generate server public key!");
				// If key not exist then generate response with error message
				return ResponseHandler.generateResponse(HttpStatus.NOT_FOUND, "err001");
			}
		} catch (Exception e) {
			LOGGER.error("Failed to generate server public key!");
			// Throws exception If an exception occurs
			throw new CPException("err001", resourceBundle.getString("err001"));
		}

	}

	/*
	 * @Description : Handles HTTP GET request for auth/serverrandomstr api and
	 * store generated server random string in DB
	 * 
	 * @Response : server's random string and key id
	 */
	@GetMapping("auth/serverrandomstr")
	public ResponseEntity<Object> getServerRandomString() throws CPException {

		LOGGER.info("Getting server random string");
		// Variable to store server's random string
		AuthKey serverRandomString = null;

		try {
			// Call to AuthService to retrieve the server's random string
			serverRandomString = authService.getServerRandomString();

			// Check server's random string successfully retrieved
			if (serverRandomString != null) {
				LOGGER.info("server random string generate successfuly");
				// If key exist then generate response with status
				return ResponseHandler.generateResponse(serverRandomString, HttpStatus.OK);
			} else {
				LOGGER.error("Failed to generate server random string!");
				// If key not exist then generate response with error message
				return ResponseHandler.generateResponse(HttpStatus.NOT_FOUND, "err002");
			}
		} catch (Exception e) {
			LOGGER.error("Failed to generate server random string!");
			// Throws exception If an exception occurs
			throw new CPException("err002", resourceBundle.getString("err002"));
		}
	}

	/*
	 * @Description : Handles HTTP POST request for auth/clientrandomstr api to
	 * store client's random string in DB
	 * 
	 * @Response : success message
	 * 
	 * @Request : AuthKey object with client's random string
	 */
	@PostMapping("auth/clientrandomstr")
	public ResponseEntity<Object> addClientRandomString(@RequestBody AuthKey authKey) throws CPException {

		LOGGER.info("Adding client's random string");
		// Variable to store client's random string
		AuthKey updatedAuthKey = null;

		try {
			// Call to AuthService to add the client's random string
			updatedAuthKey = authService.addClientRandomString(authKey);

			// Check client's random string successfully retrieved
			if (updatedAuthKey != null) {
				LOGGER.info("client's random string added successfuly");
				// If key exist then generate response with status
				return ResponseHandler.generateResponse(updatedAuthKey, HttpStatus.OK);
			} else {
				LOGGER.error("Failed to add client's random string!");
				// If key not exist then generate response with error message
				return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err003");
			}
		} catch (Exception e) {
			LOGGER.error("Failed to add client's random string!");
			// Throws exception If an exception occurs
			throw new CPException("err003", resourceBundle.getString("err003"));
		}
	}

	/*
	 * @Description : Handles HTTP POST request for auth/clientpresecretstr api to
	 * store client's presecret key in DB
	 * 
	 * @Response : success message
	 * 
	 * @Request : AuthKey object with client's presecret key
	 */
	@PostMapping("auth/clientpresecretstr")
	public ResponseEntity<Object> addClientPreSecretKey(@RequestBody AuthKey authKey) throws CPException {
		LOGGER.info("Adding client's presecret string");
		// Variable to store client's presecret string
		AuthKey updatedAuthKey = null;

		try {
			// Call to AuthService to add the client's presecret key
			updatedAuthKey = authService.addClientPreSecretKey(authKey);

			// Check client's presecret key successfully retrieved
			if (updatedAuthKey != null) {
				LOGGER.info("client's presecret key added successfuly");
				// If key exist then generate response with status
				return ResponseHandler.generateResponse(updatedAuthKey, HttpStatus.OK);
			} else {
				LOGGER.error("Failed to add client's presecret key!");
				// If key not exist then generate response with error message
				return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err004");
			}
		} catch (Exception e) {
			LOGGER.error("Failed to add client's presecret key!");
			// Throws exception If an exception occurs
			throw new CPException("err004", resourceBundle.getString("err004"));
		}
	}

	/*
	 * @Description : Handles HTTP POST request for auth/authenticate api to
	 * authenticate the user using username and password and send generated token on
	 * success
	 * 
	 * @Response : token
	 * 
	 * @Param : key id used to retrive key's from db
	 * 
	 * @Request : Username and passoword
	 */
	@PostMapping("auth/authenticate")
	public ResponseEntity<Object> generateToken(@RequestBody AuthRequest authRequest, @RequestParam("keyid") int keyId)
			throws CPException {
		LOGGER.info("Generate token for username : " + authRequest.getUsername());
		try {
			// Authenticate the user using username and password
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

			// check user is authenticate successful.
			if (authentication.isAuthenticated()) {
				LOGGER.info("User authenticated");
				// generate jwt token for authenticated user.
				String generatedToken = jwtUtil.generateToken(authRequest.getUsername(), keyId);

				// Create object to encapsulate token
				KeyDTO token = new KeyDTO(generatedToken);
				LOGGER.info("Token generated for username : " + authRequest.getUsername());
				// Return a successful response with then token.
				return ResponseHandler.generateResponse(token, HttpStatus.OK);

			} else {
				LOGGER.error("Failed to authenticate user");
				// If authentication fails then return error response
				return ResponseHandler.generateResponse(HttpStatus.INTERNAL_SERVER_ERROR, "err005");
			}

		} catch (Exception ex) {
			// Throws exception If an exception occurs during the authentication process
			throw new CPException("err005", resourceBundle.getString("err005"));
		}

	}

	/*
	 * @Description : Handles HTTP POST request for auth/token/{keyid} api to
	 * generate token before login
	 * 
	 * @Response : token
	 * 
	 * @PathVariable : key id used to retrive key's from db
	 */
	@PostMapping("auth/token/{keyid}")
	public ResponseEntity<Object> getToken(@PathVariable("keyid") int keyId) throws Exception {
		LOGGER.info("Generate token before login");
		try {

			// generate JWT token
			String generatedToken = jwtUtilWIthoutUsernamePassword.generateToken(keyId);

			// Create object to encapsulate token
			KeyDTO token = new KeyDTO(generatedToken);
			LOGGER.info("Token generated before login");
			// Return token in response
			return ResponseHandler.generateResponse(token, HttpStatus.OK);

		} catch (Exception e) {
			LOGGER.error("Failed to generate token before login");
			throw new CPException("err001", resourceBundle.getString("err006"));
		}

	}

	// for testing
	@GetMapping("/hello")
	public ResponseEntity<Object> token() {
		System.out.println("hello");
		KeyDTO token = new KeyDTO("success");
		return ResponseHandler.generateResponse(token, HttpStatus.OK);
	}
}
