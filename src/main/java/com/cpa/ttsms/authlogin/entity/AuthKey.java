package com.cpa.ttsms.authlogin.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "authkey")
public class AuthKey {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private int id;

	@Column(name = "severrandomstr")
	private String serverRandomString;

	@Column(name = "clientrandomstr")
	private String clientRandomString;

	@Column(name = "clientpresecretkey")
	private String clientPreSecretKey;

	@Column(name = "secretkey")
	private String secretKey;

	@Column(name = "initvector")
	private String initVector;

	/**
	 * 
	 */
	public AuthKey() {
		super();
	}

	/**
	 * @param id
	 * @param serverRandomString
	 * @param clientRandomString
	 * @param clientPreSecretKey
	 * @param secretKey
	 */
	public AuthKey(int id, String serverRandomString, String clientRandomString, String clientPreSecretKey,
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

	@Override
	public String toString() {
		return "AuthKey [id=" + id + ", serverRandomString=" + serverRandomString + ", clientRandomString="
				+ clientRandomString + ", clientPreSecretKey=" + clientPreSecretKey + ", secretKey=" + secretKey
				+ ", initVector=" + initVector + "]";
	}

}