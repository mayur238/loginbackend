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
	private SecretKeyUtil secretKey;

	// Extract the expiration date from the JWT token
	public Date extractExpiration(String token, int keyId) {
		return extractClaim(token, Claims::getExpiration, keyId);
	}

	// Extract a claim from JWT token using value
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, int keyId) {
		final Claims claims = extractAllClaims(token, keyId);
		return claimsResolver.apply(claims);
	}

	// Extract all claims(details) from JWT token
	private Claims extractAllClaims(String token, int keyId) {
		return Jwts.parserBuilder().setSigningKey(getSignKey(keyId)).build().parseClaimsJws(token).getBody();
	}

	// Check if the JWT token is expired
	private Boolean isTokenExpired(String token, int keyId) {
		return extractExpiration(token, keyId).before(new Date());
	}

	// Check id the JWT token is valid
	public Boolean validateToken(String token, int keyId) {
		return (!isTokenExpired(token, keyId));
	}

	// Generate the JWT token for a keyid
	public String generateToken(int keyId) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("keyid", keyId);
		return createToken(claims, keyId);
	}

	// Create JWT token for a keyid
	private String createToken(Map<String, Object> claims, int keyId) {
		return Jwts.builder().setClaims(claims).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
				.signWith(getSignKey(keyId), SignatureAlgorithm.HS256).compact();
	}

	// Get sign key based on keyid
	private Key getSignKey(int keyId) {
		final String SECRET = secretKey.getSecretKey(keyId);
		byte[] keyBytes = Decoders.BASE64.decode(SECRET + SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
