package com.cpa.ttsms.authlogin.serviceimpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.cpa.ttsms.authlogin.entity.Password;
import com.cpa.ttsms.authlogin.entity.PasswordDetails;
import com.cpa.ttsms.authlogin.repository.PasswordRepository;
import com.cpa.ttsms.authlogin.service.PasswordDetailsService;

@Component
public class PasswordDetailsServiceImpl implements PasswordDetailsService {

	@Autowired
	private PasswordRepository passRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Password userInfo = passRepository.findByUsername(username);

		UserDetails userDetails = new PasswordDetails(userInfo);
		return userDetails;
	}

}
