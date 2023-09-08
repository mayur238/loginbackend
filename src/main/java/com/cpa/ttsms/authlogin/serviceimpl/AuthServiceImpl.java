package com.cpa.ttsms.authlogin.serviceimpl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cpa.ttsms.authlogin.dto.KeyDTO;
import com.cpa.ttsms.authlogin.entity.AuthKey;
import com.cpa.ttsms.authlogin.repository.AuthRepository;
import com.cpa.ttsms.authlogin.service.AuthService;
import com.cpa.ttsms.authlogin.service.RSAService;

@Service
public class AuthServiceImpl implements AuthService {

	private static final Path PUBLIC_KEY_PATH = Path.of("src/main/resources/public_key.pem");
	private static final Path PRIVATE_KEY_PATH = Path.of("src/main/resources/private_key.pem");

	private static final String privateKeyFilePath = "src/main/resources/private_key.pem";
	private static final String publicKeyFilePath = "src/main/resources/public_key.pem";

	private static final int LENGTH_SERVER_RANDOM_STRING = 30;
	private PrivateKey privateKey;
	private PublicKey publicKey;

	@Autowired
	private AuthRepository authRepository;

	@Autowired
	private RSAService rsaService;

	@Override
	public Object getServerPublicKey() throws IOException {

		String serverPublicKey = Files.readString(PUBLIC_KEY_PATH);
		KeyDTO serverPublicKeyObject = new KeyDTO(serverPublicKey);

		return serverPublicKeyObject;
	}

	@Override
	public AuthKey getServerRandomString() {
		String serverRanodmString = null;
		String encryptedServerRandomString = null;
		serverRanodmString = generateRandomString(LENGTH_SERVER_RANDOM_STRING);
		AuthKey createdAuthKey = null;
		try {
			if (serverRanodmString != null) {

				AuthKey authKey = new AuthKey();

				encryptedServerRandomString = rsaService.encrypt(serverRanodmString);
				authKey.setServerRandomString(encryptedServerRandomString);
				createdAuthKey = authRepository.save(authKey);

				if (createdAuthKey != null) {
					System.out.println("getServerRandomString :" + createdAuthKey);
					createdAuthKey.setServerRandomString(serverRanodmString);
					return createdAuthKey;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public AuthKey addClientRandomString(AuthKey authKey) throws Exception {

		AuthKey createdAuthKey = null;
		int updatedCount = 0;
		try {

			if (authKey.getClientRandomString() != null) {
//				existingAuthKey.setClientRandomString(authKey.getClientRandomString());

				updatedCount = authRepository.updateClientRandomString(authKey.getClientRandomString(),
						authKey.getId());

				System.out.println("client random count : " + updatedCount);
				if (updatedCount > 0) {
					Optional<AuthKey> existingAuthKeyOptional = authRepository.findById(authKey.getId());
					AuthKey existingAuthKey = existingAuthKeyOptional.get();
					createdAuthKey = existingAuthKey;
					if (existingAuthKey.getServerRandomString() != null
							&& existingAuthKey.getClientRandomString() != null
							&& existingAuthKey.getClientPreSecretKey() != null) {
						String secretKey = rsaService.encrypt(generateSecretKey(existingAuthKey));

						updatedCount = authRepository.updateSecretKey(secretKey, createdAuthKey.getId());
					}
					System.out.println("addClientRandomString :" + createdAuthKey);

					return createdAuthKey;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return createdAuthKey;
	}

	@Override
	public AuthKey addClientPreSecretKey(AuthKey authKey) throws Exception {
		AuthKey createdAuthKey = null;
		int updatedCount = 0;
		try {

			if (authKey.getClientPreSecretKey() != null) {

				updatedCount = authRepository.updateClientPreSecretKey(authKey.getClientPreSecretKey(),
						authKey.getId());

				if (updatedCount > 0) {
					Optional<AuthKey> existingAuthKeyOptional = authRepository.findById(authKey.getId());
					AuthKey existingAuthKey = existingAuthKeyOptional.get();
					createdAuthKey = existingAuthKey;
					if (existingAuthKey.getServerRandomString() != null
							&& existingAuthKey.getClientRandomString() != null
							&& existingAuthKey.getClientPreSecretKey() != null) {
						String secretKey = rsaService.encrypt(generateSecretKey(existingAuthKey));

						updatedCount = authRepository.updateSecretKey(secretKey, createdAuthKey.getId());
					}
					System.out.println("addClientPreSecretKey :" + createdAuthKey);
					return createdAuthKey;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return createdAuthKey;
	}

	@Override
	public AuthKey getAuthKeyByKeyId(int keyId) {

		AuthKey authKey = null;
		try {

			Optional<AuthKey> existingAuthKey = authRepository.findById(keyId);

			if (existingAuthKey.isPresent()) {
				authKey = existingAuthKey.get();
				System.out.println("getAuthKeyByKeyId :" + authKey);
				if (authKey != null) {
					return authKey;
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private String generateRandomString(int length) {
		try {
			String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
			StringBuilder randomString = new StringBuilder(length);
			SecureRandom random = new SecureRandom();

			for (int i = 0; i < length; i++) {
				int randomIndex = random.nextInt(characters.length());
				char randomChar = characters.charAt(randomIndex);
				randomString.append(randomChar);
			}
			return randomString.toString();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
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

	public String getSecretKey(int keyId) {
		Optional<AuthKey> existingAuthKeyOptional = authRepository.findById(keyId);
		AuthKey existingAuthKey = existingAuthKeyOptional.get();
		System.out.println("getSecreteKey : " + existingAuthKey);
		String encryptedSecretKey = existingAuthKey.getSecretKey();

		try {
			return rsaService.decrypt(encryptedSecretKey);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
