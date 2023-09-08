package com.cpa.ttsms.authlogin.repository;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.cpa.ttsms.authlogin.entity.AuthKey;

@Repository
public interface AuthRepository extends JpaRepository<AuthKey, Integer> {
	Optional<AuthKey> findById(int keyId);

	@Transactional
	@Modifying
	@Query(value = "UPDATE authkey ak set serverrandomstr = ?1 where ak.id = ?2", nativeQuery = true)
	int updateServerRandomString(String serverRandomString, int keyId);

	@Transactional
	@Modifying
	@Query(value = "UPDATE authkey ak set clientrandomstr = ?1 where ak.id = ?2", nativeQuery = true)
	int updateClientRandomString(String clientRandomString, int keyId);

	@Transactional
	@Modifying
	@Query(value = "UPDATE authkey ak set clientpresecretkey = ?1 where ak.id = ?2", nativeQuery = true)
	int updateClientPreSecretKey(String clientPreSecretKey, int keyId);

	@Transactional
	@Modifying
	@Query(value = "UPDATE authkey ak set secretkey = ?1 where ak.id = ?2", nativeQuery = true)
	int updateSecretKey(String secretKey, int keyId);
}
