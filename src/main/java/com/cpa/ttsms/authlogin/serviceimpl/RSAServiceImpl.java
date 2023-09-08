package com.cpa.ttsms.authlogin.serviceimpl;

import java.io.File;
import java.io.FileReader;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Service;

import com.cpa.ttsms.authlogin.service.RSAService;

@Service
public class RSAServiceImpl implements RSAService {

	private static final Path PUBLIC_KEY_PATH = Path.of("src/main/resources/public_key.pem");
	private static final Path PRIVATE_KEY_PATH = Path.of("src/main/resources/private_key.pem");

	private static final String privateKeyFilePath = "src/main/resources/private_key.pem";
	private static final String publicKeyFilePath = "src/main/resources/public_key.pem";

	private static final int LENGTH_SERVER_RANDOM_STRING = 30;
	private PrivateKey privateKey;
	private PublicKey publicKey;

	@PostConstruct
	public void init() throws Exception {
		readPrivateKey();
		readPublicKey();
	}

	@Override
	public PrivateKey readPrivateKey() throws Exception {
		File file = new File(privateKeyFilePath);
		KeyFactory factory = KeyFactory.getInstance("RSA");

		try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {

			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
			privateKey = ((PrivateKey) factory.generatePrivate(privKeySpec));
			System.out.println(privateKey);
			return privateKey;
		}
	}

	@Override
	public PublicKey readPublicKey() throws Exception {
		File file = new File(publicKeyFilePath);
		KeyFactory factory = KeyFactory.getInstance("RSA");

		try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {

			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
			publicKey = ((PublicKey) factory.generatePublic(pubKeySpec));
			return publicKey;
		}
	}

	@Override
	public String decrypt(String encryptedData) throws Exception {
		System.out.println("encryptedData :" + encryptedData);
		byte[] encryptedBytes = decode(encryptedData);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
		return new String(decryptedMessage, "UTF8");
	}

	private byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}

	@Override
	public String encrypt(String message) throws Exception {

		byte[] messageToBytes = message.getBytes();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		System.out.println("public key " + publicKey);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedBytes = cipher.doFinal(messageToBytes);
		System.out.println(encryptedBytes);
		return encode(encryptedBytes);
	}

	private String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
}
