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
	private SecretKey secretKey;

	public String extractUsername(String token, int keyId) {
		return extractClaim(token, Claims::getSubject, keyId);
	}

	public Date extractExpiration(String token, int keyId) {
		return extractClaim(token, Claims::getExpiration, keyId);
	}

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

	public Boolean validateToken(String token, UserDetails userDetails, int keyId) {
		final String username = extractUsername(token, keyId);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token, keyId));
	}

	public String generateToken(String userName, int keyId) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userName, keyId);
	}

	private String createToken(Map<String, Object> claims, String userName, int keyId) {
		return Jwts.builder().setClaims(claims).setSubject(userName).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
				.signWith(getSignKey(keyId), SignatureAlgorithm.HS256).compact();
	}

	private Key getSignKey(int keyId) {
		final String SECRET = secretKey.getSecretKey(keyId);
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
