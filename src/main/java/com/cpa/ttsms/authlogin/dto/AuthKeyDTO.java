package com.cpa.ttsms.authlogin.dto;

public class AuthKeyDTO {

	private int id;

	private String serverRandomString;

	private String clientRandomString;

	private String clientPreSecretKey;

	private String secretKey;

	private String initVector;

	/**
	 * 
	 */
	public AuthKeyDTO() {
		super();
	}

	/**
	 * @param id
	 * @param serverRandomString
	 * @param clientRandomString
	 * @param clientPreSecretKey
	 * @param secretKey
	 * @param initVector
	 */
	public AuthKeyDTO(int id, String serverRandomString, String clientRandomString, String clientPreSecretKey,
			String secretKey, String initVector) {
		super();
		this.id = id;
		this.serverRandomString = serverRandomString;
		this.clientRandomString = clientRandomString;
		this.clientPreSecretKey = clientPreSecretKey;
		this.secretKey = secretKey;
		this.initVector = initVector;
	}

	/**
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * @return the serverRandomString
	 */
	public String getServerRandomString() {
		return serverRandomString;
	}

	/**
	 * @param serverRandomString the serverRandomString to set
	 */
	public void setServerRandomString(String serverRandomString) {
		this.serverRandomString = serverRandomString;
	}

	/**
	 * @return the clientRandomString
	 */
	public String getClientRandomString() {
		return clientRandomString;
	}

	/**
	 * @param clientRandomString the clientRandomString to set
	 */
	public void setClientRandomString(String clientRandomString) {
		this.clientRandomString = clientRandomString;
	}

	/**
	 * @return the clientPreSecretKey
	 */
	public String getClientPreSecretKey() {
		return clientPreSecretKey;
	}

	/**
	 * @param clientPreSecretKey the clientPreSecretKey to set
	 */
	public void setClientPreSecretKey(String clientPreSecretKey) {
		this.clientPreSecretKey = clientPreSecretKey;
	}

	/**
	 * @return the secretKey
	 */
	public String getSecretKey() {
		return secretKey;
	}

	/**
	 * @param secretKey the secretKey to set
	 */
	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	/**
	 * @return the initVector
	 */
	public String getInitVector() {
		return initVector;
	}

	/**
	 * @param initVector the initVector to set
	 */
	public void setInitVector(String initVector) {
		this.initVector = initVector;
	}

}
