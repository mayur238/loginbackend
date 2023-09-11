package com.cpa.ttsms.authlogin.serviceimpl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Optional;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cpa.ttsms.authlogin.controller.AuthController;
import com.cpa.ttsms.authlogin.dto.KeyDTO;
import com.cpa.ttsms.authlogin.entity.AuthKey;
import com.cpa.ttsms.authlogin.repository.AuthRepository;
import com.cpa.ttsms.authlogin.service.AuthService;
import com.cpa.ttsms.authlogin.service.RSAService;

@Service
public class AuthServiceImpl implements AuthService {

	private static final Path PUBLIC_KEY_PATH = Path.of("src/main/resources/public_key.pem");
//	private static final Path PRIVATE_KEY_PATH = Path.of("src/main/resources/private_key.pem");

//	private static final String privateKeyFilePath = "src/main/resources/private_key.pem";
//	private static final String publicKeyFilePath = "src/main/resources/public_key.pem";

	private static final int LENGTH_SERVER_RANDOM_STRING = 30;
//	private PrivateKey privateKey;
//	private PublicKey publicKey;

	@Autowired
	private AuthRepository authRepository;

	@Autowired
	private RSAService rsaService;

	// The logger is used for logging messages related to this class.
	private static Logger LOGGER;

	AuthServiceImpl() {
		LOGGER = Logger.getLogger(AuthController.class);
	}

	// This method returns the server's public key.
	@Override
	public Object getServerPublicKey() throws IOException {

		LOGGER.info("Getting Servcer public key from file");
		// Read public key from file and wrap it in KeyDTO object
		String serverPublicKey = Files.readString(PUBLIC_KEY_PATH);
		KeyDTO serverPublicKeyObject = new KeyDTO(serverPublicKey);

		return serverPublicKeyObject;
	}

	// This method generates server random string and stores in DB
	@Override
	public AuthKey getServerRandomString() {
		LOGGER.info("Getting server random string..");
		String serverRanodmString = null;
		String encryptedServerRandomString = null;

		// generate server random string
		serverRanodmString = generateRandomString(LENGTH_SERVER_RANDOM_STRING);

		AuthKey createdAuthKey = null;
		try {

			// Check if server random string is empty
			if (serverRanodmString != null) {
				LOGGER.info("Server Random String generated.");
				// Create a new AuthKey object
				AuthKey authKey = new AuthKey();

				// encrypt the server random string.
				encryptedServerRandomString = rsaService.encrypt(serverRanodmString);
				authKey.setServerRandomString(encryptedServerRandomString);

				// Save the AuthKey in DB
				createdAuthKey = authRepository.save(authKey);

				if (createdAuthKey != null) {
					LOGGER.info("Server random string add successfuly in DB.");
					createdAuthKey.setServerRandomString(serverRanodmString);
					return createdAuthKey;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		LOGGER.error("Failed to generate/ add server random string");
		return null;
	}

	// // This method updates the client's random string in the AuthKey object.
	@Override
	public AuthKey addClientRandomString(AuthKey authKey) throws Exception {
		LOGGER.info("Adding client random string..");
		AuthKey createdAuthKey = null;
		int updatedCount = 0;
		try {

			if (authKey.getClientRandomString() != null) {
//				existingAuthKey.setClientRandomString(authKey.getClientRandomString());
				// Update the client random string in the DB
				updatedCount = authRepository.updateClientRandomString(authKey.getClientRandomString(),
						authKey.getId());

				/*
				 * Check client random string is update (if greator than o means it's updated)
				 * when we have all 3 keys then generate secret key and store in DB
				 */
				if (updatedCount > 0) {
					LOGGER.info("Client random string added successfuly.");
					Optional<AuthKey> existingAuthKeyOptional = authRepository.findById(authKey.getId());
					AuthKey existingAuthKey = existingAuthKeyOptional.get();
					createdAuthKey = existingAuthKey;
					if (areAllAuthKeysAvailable(existingAuthKey)) {
						LOGGER.info("All Keys available to generate secret keys.");
						String secretKey = rsaService.encrypt(generateSecretKey(existingAuthKey));

						updatedCount = authRepository.updateSecretKey(secretKey, createdAuthKey.getId());
						LOGGER.info("Generated Secret key added successfuly");
					}

					return createdAuthKey;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		LOGGER.error("Failed to generate/ add Client random string");
		return null;
	}

	// This method updates the client's pre-secret key in the AuthKey object.
	@Override
	public AuthKey addClientPreSecretKey(AuthKey authKey) throws Exception {
		LOGGER.info("Adding client random string..");
		AuthKey createdAuthKey = null;
		int updatedCount = 0;
		try {

			if (authKey.getClientPreSecretKey() != null) {
				// Update the client presecret key in the DB
				updatedCount = authRepository.updateClientPreSecretKey(authKey.getClientPreSecretKey(),
						authKey.getId());

				/*
				 * Check client random string is update (if greator than o means it's updated)
				 * when we have all 3 keys then generate secret key and store in DB
				 */
				if (updatedCount > 0) {
					LOGGER.info("Client random string added successfuly.");
					Optional<AuthKey> existingAuthKeyOptional = authRepository.findById(authKey.getId());
					AuthKey existingAuthKey = existingAuthKeyOptional.get();
					createdAuthKey = existingAuthKey;
					if (areAllAuthKeysAvailable(existingAuthKey)) {
						LOGGER.info("All Keys available to generate secret keys.");
						String secretKey = rsaService.encrypt(generateSecretKey(existingAuthKey));

						updatedCount = authRepository.updateSecretKey(secretKey, createdAuthKey.getId());
						LOGGER.info("Generated Secret key added successfuly");
					}
					return createdAuthKey;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		LOGGER.error("Failed to generate/ add Client Presecret key");
		return createdAuthKey;
	}

	// This method retrieves an AuthKey by its key ID.
	@Override
	public AuthKey getAuthKeyByKeyId(int keyId) {
		LOGGER.info("Get keys by unique key id..");
		try {

			Optional<AuthKey> existingAuthKey = authRepository.findById(keyId);
			if (existingAuthKey.isPresent()) {
				LOGGER.info("AuthKey exist for id : " + keyId);
				return existingAuthKey.get();
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		LOGGER.error("AuthKey not exist for id : " + keyId);
		return null;
	}

	// This method generates a random string of the specified length.
	private String generateRandomString(int length) {
		LOGGER.info("Generating Random String..");
		try {
			String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
			StringBuilder randomString = new StringBuilder(length);
			SecureRandom random = new SecureRandom();

			for (int i = 0; i < length; i++) {
				int randomIndex = random.nextInt(characters.length());
				char randomChar = characters.charAt(randomIndex);
				randomString.append(randomChar);
			}
			LOGGER.info("Random String generated ..");
			return randomString.toString();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		LOGGER.error("Failed to generate random string");
		return null;
	}

	// This method generates a secret key based
	private String generateSecretKey(AuthKey authKey) {
		LOGGER.info("Generating secret key");
		String key = null;
		try {
			key = rsaService.decrypt(authKey.getServerRandomString())
					+ rsaService.decrypt(authKey.getClientRandomString())
					+ rsaService.decrypt(authKey.getClientPreSecretKey());
			LOGGER.info("Secret key generated ..");
			return key;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		LOGGER.error("Failed to generate secret key");
		return null;
	}

	// This method retrieves the decrypted secret key for an AuthKey by its key ID.
	public String getSecretKey(int keyId) {
		LOGGER.info("Get secret key");
		Optional<AuthKey> existingAuthKeyOptional = authRepository.findById(keyId);
		AuthKey existingAuthKey = existingAuthKeyOptional.get();

		String encryptedSecretKey = existingAuthKey.getSecretKey();
		LOGGER.info("Secret key exist");
		try {
			return rsaService.decrypt(encryptedSecretKey);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		LOGGER.error("Failed to get secret key");
		return null;
	}

	// This method checks if all required AuthKey properties are available.
	private boolean areAllAuthKeysAvailable(AuthKey authKey) {
		LOGGER.info("Checking all keys available..");
		return authKey.getServerRandomString() != null && authKey.getClientRandomString() != null
				&& authKey.getClientPreSecretKey() != null;
	}
}
