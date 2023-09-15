package com.cpa.ttsms.authlogin.serviceimpl;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cpa.ttsms.authlogin.service.AESService;
import com.cpa.ttsms.authlogin.util.SecretKeyUtil;

@Service
public class AESServiceImpl implements AESService {

	private SecretKey SECRET_KEY;
	private String initVector;
	@Autowired
	private SecretKeyUtil secretKeyObject;

	@Override
	public String decrypt(String encryptedData, int keyId) throws Exception {
		try {
			SECRET_KEY = getKey(keyId);
//			String secretKey = "GpmBWZLFVhuZdlXEP0YQcaQiTmA46mOm";
//			byte[] encryptedBytes = decode(encryptedData);
//			Cipher cipher = Cipher.getInstance("AES");
//			cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY);
//			byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
//			return new String(decryptedMessage, "UTF8");

//			byte[] encryptedBytes = decode(encryptedData);
//			System.out.println(encryptedData.getBytes());
			System.out.println("keyId : " + keyId);
			initVector = getInitVector(keyId);

//			SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
//			System.out.println("secret key : " + key.toString());
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(SECRET_KEY.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedData.getBytes()));
			System.out.println(new String(original));
			return new String(original);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	private byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}

	@Override
	public String encrypt(String data, int keyId) throws Exception {

		try {
			SECRET_KEY = getKey(keyId);
			String secretKey = "BeSk5FRncm5trpspdE2Iqz0aUz0SnTq4";
//			byte[] messageToBytes = message.getBytes();
//			Cipher cipher = Cipher.getInstance("AES");
//			cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY);
//			byte[] encryptedBytes = cipher.doFinal(messageToBytes);
//			return encode(encryptedBytes);
			initVector = getInitVector(keyId);
			SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.toString().getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

			byte[] encrypted = cipher.doFinal(data.getBytes());
			System.out.println(encode(encrypted));

			return encode(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public SecretKey getKey(int keyId) {
		SECRET_KEY = new SecretKeySpec(secretKeyObject.getSecretKey(keyId).getBytes(), "AES");
		System.out.println("key : " + SECRET_KEY);
		return SECRET_KEY;
	}

	public String getInitVector(int keyId) {
		initVector = secretKeyObject.getInitVector(keyId);
		System.out.println("initVector : " + initVector);
		return initVector;
	}

}
