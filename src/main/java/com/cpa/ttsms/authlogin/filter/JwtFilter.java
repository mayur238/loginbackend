package com.cpa.ttsms.authlogin.filter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.cpa.ttsms.authlogin.config.Constants;
import com.cpa.ttsms.authlogin.entity.Password;
import com.cpa.ttsms.authlogin.service.AESService;
import com.cpa.ttsms.authlogin.service.PasswordDetailsService;
import com.cpa.ttsms.authlogin.util.JwtUtil;
import com.cpa.ttsms.authlogin.util.RequestWrapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private PasswordDetailsService service;

	@Autowired
	private AESService rsaService;

	@Override
	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			FilterChain filterChain) throws ServletException, IOException {

		System.out.println("inside jwtfilter");
		// Extract the JWT token from the Authorization header
		String authorizationHeader = httpServletRequest.getHeader("Authorization");

		RequestWrapper requestWrapper = new RequestWrapper(httpServletRequest);
		String token = null;
		String userName = null;

		// Check if the request contains the "keyid" parameter
		if (httpServletRequest.getParameterMap().containsKey("keyid")) {

			// Convert parameter from string to number
			int keyId = Integer.parseInt(httpServletRequest.getParameter("keyid"));

			// Wrap the request to allow reading the request body multiple times

			System.out.println(requestWrapper.getServletPath());
			if (!(requestWrapper.getServletPath().matches(Constants.UN_SECURE_PATH)
					|| (requestWrapper.getServletPath().equals(Constants.TOKEN_BEFORE_LOGIN_PATH))
					|| (requestWrapper.getServletPath().equals(Constants.AUTHENTICATE_PATH)))) {
				System.out.println("inside if");
				// Check if the request has a content type and a body
				if (requestWrapper.getContentType() != null && requestWrapper.getContentLength() > 0) {
//					byte[] body = StreamUtils.copyToByteArray(requestWrapper.getInputStream());

					try {
						StringBuilder payload = new StringBuilder();
						try (BufferedReader reader = requestWrapper.getReader()) {
							String line;
							while ((line = reader.readLine()) != null) {
								payload.append(line);
							}
						}

						// Now you have the payload data in the 'payload' variable
						String payloadData = payload.toString();
						System.out.println("body : " + payloadData);
						String requestBody = rsaService.decrypt(payloadData, keyId);

						ObjectMapper objectMapper = new ObjectMapper();
						JsonNode jsonNode = objectMapper.readTree(requestBody);

						System.out.println("string : " + requestBody);
						// Decrypt the data using the decryptData method
						Object requestBodyObject = objectMapper.treeToValue(jsonNode, Object.class);
						System.out.println("object : " + jsonNode);
						// Serialize the decrypted data back to JSON
						String json = objectMapper.writeValueAsString(requestBodyObject);
						System.out.println("object2 : " + jsonNode.get("username"));
						byte[] newRequestBodyBytes = json.getBytes(StandardCharsets.UTF_8);
						requestWrapper.setInputStream(new ByteArrayInputStream(newRequestBodyBytes).readAllBytes());
					} catch (JsonProcessingException e) {
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

			}

			// Checks if the authorization header contains valid bearer token
			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				token = authorizationHeader.substring(7);

				// Extract username from token
				userName = jwtUtil.extractUsername(token, keyId);
			}

			if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {

				// Load user details using extracted username
				UserDetails userDetails = service.loadUserByUsername(userName);

				// Validate the token
				if (jwtUtil.validateToken(token, userDetails, keyId)) {

					// set token in the security context
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());
					usernamePasswordAuthenticationToken
							.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				}
			}
		}

		// Continue with the filter chain
		filterChain.doFilter(requestWrapper, httpServletResponse);
	}

//	// Helper method to decrypt the request data
//	private Object decryptData(JsonNode jsonNode) {
//		// ObjectMapper objectMapper = new ObjectMapper();
//
//		Password password = new Password();
//		try {
//			String dataObject = rsaService.decrypt(jsonNode.get("username").asText());
//
//			password.setUsername(decryptedUsername);
//			password.setPassword(decryptedPassword);
//			System.out.println("Decrypted Username: " + decryptedUsername);
//			System.out.println("Decrypted Password: " + decryptedPassword);
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//		return password;
//	}

	private Object decryptData(JsonNode jsonNode) {
		// ObjectMapper objectMapper = new ObjectMapper();

		Password password = new Password();
		try {
			String decryptedUsername = (jsonNode.get("username").asText());
			String decryptedPassword = (jsonNode.get("password").asText());

			password.setUsername(decryptedUsername);
			password.setPassword(decryptedPassword);
			System.out.println("Decrypted Username: " + decryptedUsername);
			System.out.println("Decrypted Password: " + decryptedPassword);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return password;
	}

}
