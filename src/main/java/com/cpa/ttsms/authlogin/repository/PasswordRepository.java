package com.cpa.ttsms.authlogin.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.cpa.ttsms.authlogin.entity.Password;

@Repository
public interface PasswordRepository extends JpaRepository<Password, Integer> {

	// Find Password by its username
	Password findByUsername(String username);
}
