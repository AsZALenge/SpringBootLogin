package com.auth.dao;

import org.springframework.data.repository.CrudRepository;

import com.auth.entity.UserEntity;

public interface UserRepository extends CrudRepository<UserEntity, Long> {
	UserEntity findByUsername(String username);
	
}
