package com.cpa.ttsms.authlogin.config;

public interface Constants {
	public static final String UN_SECURE_PATH = "/auth/serverpublickey|/auth/serverrandomstr|/auth/clientrandomstr|/auth/clientpresecretstr|auth/initvector";

	public static final String AUTHENTICATE_PATH = "/auth/authenticate";

	public static final String SERVER_PUBLIC_KEY_PATH = "/auth/serverpublickey";

	public static final String SERVER_RANDOM_STRING_PATH = "/auth/serverrandomstr";

	public static final String CLIENT_RANDOM_STRING_PATH = "/auth/clientrandomstr";

	public static final String CLIENT_PRESECRET_KEY_PATH = "/auth/clientpresecretstr";

	public static final String TOKEN_BEFORE_LOGIN_PATH = "/auth/token/**";

	public static final String INIT_VECTOR = "/auth/initvector";
}
