package com.cpa.ttsms.authlogin.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cpa.ttsms.authlogin.filter.JwtFilter;
import com.cpa.ttsms.authlogin.filter.JwtFilterWithoutUsernamePassword;
import com.cpa.ttsms.authlogin.serviceimpl.PasswordDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private JwtFilter jwtFilter;

	@Autowired
	private JwtFilterWithoutUsernamePassword jwtFilterWithoutUsernamePassword;

	// Service to load user details for authentication
	@Bean
	public UserDetailsService userDetailsService() {
		return new PasswordDetailsServiceImpl();
	}

	@Bean
	@Order(1)
	public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
		return http.cors().and().csrf().disable().antMatcher(Constants.AUTHENTICATE_PATH).authorizeHttpRequests()
				.anyRequest().authenticated().and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.authenticationProvider(authenticationProvider())
				.addFilterBefore(jwtFilterWithoutUsernamePassword, UsernamePasswordAuthenticationFilter.class).build();

	}

	@Bean
	@Order(2)
	public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
		return http.cors().and().csrf().disable().authorizeHttpRequests()
				.antMatchers(Constants.SERVER_PUBLIC_KEY_PATH, Constants.SERVER_RANDOM_STRING_PATH,
						Constants.CLIENT_RANDOM_STRING_PATH, Constants.CLIENT_PRESECRET_KEY_PATH,
						Constants.TOKEN_BEFORE_LOGIN_PATH, Constants.INIT_VECTOR)
				.permitAll().and().authorizeHttpRequests().anyRequest().authenticated().and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.authenticationProvider(authenticationProvider())
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class).build();

	}

	// Password encoder for securely storing and comparing passwords
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// Authentication provider for custom authentication logic
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		return authenticationProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
}
