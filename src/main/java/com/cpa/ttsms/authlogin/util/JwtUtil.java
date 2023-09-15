package com.cpa.ttsms.authlogin.util;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

	@Autowired
	private SecretKeyUtil secretKey;

	// Extract the username from the JWT token
	public String extractUsername(String token, int keyId) {
		return extractClaim(token, Claims::getSubject, keyId);
	}

	// Extract the expiration date from the JWT token
	public Date extractExpiration(String token, int keyId) {
		return extractClaim(token, Claims::getExpiration, keyId);
	}

	// Extract a claims(details) from the JWT token using value
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, int keyId) {
		final Claims claims = extractAllClaims(token, keyId);
		return claimsResolver.apply(claims);
	}

	// Extract all claims(details) from the JWT token
	private Claims extractAllClaims(String token, int keyId) {
		return Jwts.parserBuilder().setSigningKey(getSignKey(keyId)).build().parseClaimsJws(token).getBody();
	}

	// Check if the JWT token is expired
	private Boolean isTokenExpired(String token, int keyId) {
		return extractExpiration(token, keyId).before(new Date());
	}

	// Validate the JWT token
	public Boolean validateToken(String token, UserDetails userDetails, int keyId) {
		final String username = extractUsername(token, keyId);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token, keyId));
	}

	// Generate a new JWT token for a given username and keyId
	public String generateToken(String userName, int keyId) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userName, keyId);
	}

	// Create a new JWT token
	private String createToken(Map<String, Object> claims, String userName, int keyId) {
		return Jwts.builder().setClaims(claims).setSubject(userName).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
				.signWith(getSignKey(keyId), SignatureAlgorithm.HS256).compact();
	}

	// Get the signing key based on the keyId
	private Key getSignKey(int keyId) {
		final String SECRET = secretKey.getSecretKey(keyId);
		byte[] keyBytes = Decoders.BASE64.decode(SECRET + SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
