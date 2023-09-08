package com.cpa.ttsms.authlogin.util;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtilWithoutUsernamePassword {

	@Autowired
	private SecretKey secretKey;

	public Date extractExpiration(String token, int keyId) {
		return extractClaim(token, Claims::getExpiration, keyId);
	}

//	public int extractKeyId(String token, int keyId) {
//		int keyId2 = extractClaim(token, claims -> claims.get("keyid", Integer.class), keyId);
//		return keyId2;
//	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, int keyId) {
		final Claims claims = extractAllClaims(token, keyId);
		return claimsResolver.apply(claims);
	}

	private Claims extractAllClaims(String token, int keyId) {
		return Jwts.parserBuilder().setSigningKey(getSignKey(keyId)).build().parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token, int keyId) {
		return extractExpiration(token, keyId).before(new Date());
	}

	public Boolean validateToken(String token, int keyId) {
		return (!isTokenExpired(token, keyId));
	}

	public String generateToken(int keyId) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("keyid", keyId);
		return createToken(claims, keyId);
	}

	private String createToken(Map<String, Object> claims, int keyId) {
		return Jwts.builder().setClaims(claims).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
				.signWith(getSignKey(keyId), SignatureAlgorithm.HS256).compact();
	}

	private Key getSignKey(int keyId) {
		final String SECRET = secretKey.getSecretKey(keyId);
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
