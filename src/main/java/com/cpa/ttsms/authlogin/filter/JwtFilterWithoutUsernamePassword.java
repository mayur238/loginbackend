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
		// Wrap the request
		RequestWrapper requestWrapper = new RequestWrapper(httpServletRequest);

		if (requestWrapper.getServletPath().matches(
				"/auth/serverpublickey|/auth/serverrandomstr|/auth/clientrandomstr|/auth/clientpresecretstr")) {
			System.out.println("only");
			filterChain.doFilter(requestWrapper, httpServletResponse);
			return;
		}
		if (requestWrapper.getServletPath().matches("/auth/authenticate")) {
			// Check if the request has a content type and a body
			if (requestWrapper.getContentType() != null && requestWrapper.getContentLength() > 0) {
				byte[] body = StreamUtils.copyToByteArray(requestWrapper.getInputStream());

				try {

					ObjectMapper objectMapper = new ObjectMapper();

					JsonNode jsonNode = objectMapper.readTree(body);

					// Decrypt the data using your decryptData method
					Password password = (Password) decryptData(jsonNode);

					String json = objectMapper.writeValueAsString(password);

					byte[] newRequestBodyBytes = json.getBytes(StandardCharsets.UTF_8);
					requestWrapper.setInputStream(new ByteArrayInputStream(newRequestBodyBytes).readAllBytes());

				} catch (JsonProcessingException e) {
					e.printStackTrace();
				}
			}

		}

		String authorizationHeader = httpServletRequest.getHeader("Authorization");
		String token = null;
		if (httpServletRequest.getParameterMap().containsKey("keyid")) {

			int keyId = Integer.parseInt(httpServletRequest.getParameter("keyid"));
			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				token = authorizationHeader.substring(7);

				if (token != null) {
					if (jwtUtilWIthoutUsernamePassword.validateToken(token, keyId)) {
						UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
								null, null, null);
						SecurityContextHolder.getContext().setAuthentication(authenticationToken);

					}
				}
			}
		}

		filterChain.doFilter(requestWrapper, httpServletResponse);
	}

	private Object decryptData(Object object) {
		System.out.println("here : " + object);
		ObjectMapper objectMapper = new ObjectMapper();

		// Convert the Map to a JsonNode
		JsonNode jsonNode = objectMapper.convertValue(object, JsonNode.class);

		Password password = new Password();
		try {

			String decryptedUsername = rsaService.decrypt(((JsonNode) jsonNode).get("username").asText());
			String decryptedPassword = rsaService.decrypt(((JsonNode) jsonNode).get("password").asText());

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
