package com.cpa.ttsms.authlogin.filter;

import java.io.IOException;

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

import com.cpa.ttsms.authlogin.service.PasswordDetailsService;
import com.cpa.ttsms.authlogin.util.JwtUtil;

@Component
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private PasswordDetailsService service;

	@Override
	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			FilterChain filterChain) throws ServletException, IOException {

		// Extract the JWT token from the Authorization header
		String authorizationHeader = httpServletRequest.getHeader("Authorization");

		String token = null;
		String userName = null;

		// Check if the request contains the "keyid" parameter
		if (httpServletRequest.getParameterMap().containsKey("keyid")) {

			// Convert parameter from string to number
			int keyId = Integer.parseInt(httpServletRequest.getParameter("keyid"));

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
		filterChain.doFilter(httpServletRequest, httpServletResponse);
	}

}
