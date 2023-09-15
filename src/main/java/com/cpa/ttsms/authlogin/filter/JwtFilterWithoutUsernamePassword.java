package com.cpa.ttsms.authlogin.filter;

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
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.cpa.ttsms.authlogin.config.Constants;
import com.cpa.ttsms.authlogin.entity.Password;
import com.cpa.ttsms.authlogin.service.RSAService;
import com.cpa.ttsms.authlogin.util.JwtUtilWithoutUsernamePassword;
import com.cpa.ttsms.authlogin.util.RequestWrapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class JwtFilterWithoutUsernamePassword extends OncePerRequestFilter {

	@Autowired
	private JwtUtilWithoutUsernamePassword jwtUtilWIthoutUsernamePassword;

	@Autowired
	private RSAService rsaService;

	@Override
	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			FilterChain filterChain) throws ServletException, IOException {

		// Wrap the request to allow reading the request body multiple times
		RequestWrapper requestWrapper = new RequestWrapper(httpServletRequest);

		// Check if the request matches certain paths that require no processing
		if (matchesUnsecuredPaths(requestWrapper)) {
			filterChain.doFilter(requestWrapper, httpServletResponse);
			return;
		}

		// For the "/auth/authenticate" path, decrypt the request body if present
		if (isAuthenticatePath(requestWrapper)) {
			processAuthenticationRequest(requestWrapper);
		}

		// Check for a JWT token in the Authorization header
		processJwtToken(httpServletRequest);

		// Continue with the filter chain
		filterChain.doFilter(requestWrapper, httpServletResponse);
	}

	// Helper method to check if the request path matches unsecured paths
	private boolean matchesUnsecuredPaths(RequestWrapper requestWrapper) {
		String path = requestWrapper.getServletPath();
		return path.matches(Constants.UN_SECURE_PATH);
	}

	// Helper method to check if the request path is "/auth/authenticate"
	private boolean isAuthenticatePath(RequestWrapper requestWrapper) {
		return requestWrapper.getServletPath().equals(Constants.AUTHENTICATE_PATH);
	}

	// Helper method to process the request body for authentication
	private void processAuthenticationRequest(RequestWrapper requestWrapper) throws IOException {
		// Check if the request has a content type and a body
		if (requestWrapper.getContentType() != null && requestWrapper.getContentLength() > 0) {
			byte[] body = StreamUtils.copyToByteArray(requestWrapper.getInputStream());
			System.out.println("auth boidy : " + body);
			try {
				ObjectMapper objectMapper = new ObjectMapper();
				JsonNode jsonNode = objectMapper.readTree(body);

				// Decrypt the data using the decryptData method
				Password password = (Password) decryptData(jsonNode);
				System.out.println("object  : " + password.toString());
				// Serialize the decrypted data back to JSON
				String json = objectMapper.writeValueAsString(password);
				byte[] newRequestBodyBytes = json.getBytes(StandardCharsets.UTF_8);
				requestWrapper.setInputStream(new ByteArrayInputStream(newRequestBodyBytes).readAllBytes());

			} catch (JsonProcessingException e) {
				e.printStackTrace();
			}
		}
	}

	// Helper method to process JWT token in the Authorization header
	private void processJwtToken(HttpServletRequest httpServletRequest) {
		String authorizationHeader = httpServletRequest.getHeader("Authorization");
		String token = null;

		if (httpServletRequest.getParameterMap().containsKey("keyid")) {
			int keyId = Integer.parseInt(httpServletRequest.getParameter("keyid"));

			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				token = authorizationHeader.substring(7);

				if (token != null && jwtUtilWIthoutUsernamePassword.validateToken(token, keyId)) {
					// Create an empty authentication token and set it in the security context
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
							null, null, null);
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				}
			}
		}
	}

	// Helper method to decrypt the request data
	private Object decryptData(JsonNode jsonNode) {
		// ObjectMapper objectMapper = new ObjectMapper();

		Password password = new Password();
		try {
			String decryptedUsername = rsaService.decrypt(jsonNode.get("username").asText());
			String decryptedPassword = rsaService.decrypt(jsonNode.get("password").asText());

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
