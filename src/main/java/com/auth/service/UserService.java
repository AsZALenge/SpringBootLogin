package com.auth.service;

import java.util.List;

import com.auth.entity.UserEntity;

public interface UserService {

	public UserEntity save(UserEntity user) throws Exception;
	
	public UserEntity updateUser(UserEntity id) throws Exception;

	public List<UserEntity> findAll() throws Exception;
	
	public UserEntity findUserByUsername(String username) throws Exception;

	public void delete(long id) throws Exception;

}
