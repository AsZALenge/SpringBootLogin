package com.auth.service.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.dao.UserRepository;
import com.auth.entity.UserEntity;
import com.auth.service.UserService;

@Service(value = "userService")
public class UserServiceImpl implements UserDetailsService, UserService {

	@Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username);
        
        if (user == null) {
        	throw new RuntimeException("User not found: " + username);
        }
        
        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRoleEntity().getRole_name());
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), Arrays.asList(authority));
    }

	@Override
	public UserEntity save(UserEntity user) throws Exception {
		UserEntity userEntity = userRepository.findByUsername(user.getUsername());
		
		if (userEntity != null) {
			throw new RuntimeException("username is duplicated: " + user.getUsername());
		}
		
		user.setId(0);
		user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
		user.setStatus("active");
		return userRepository.save(user);
	}
	
	@Override
	public UserEntity updateUser(UserEntity user) throws Exception {
		if (user != null && user.getId() > 0) {
			UserEntity entity = convertDtoToEntit(user);
			userRepository.save(entity);
		}else {
			throw new NullPointerException("updateUser :: UserEntity is Null or id < 0 !");
		}
		return user;
	}

	@Override
	public List<UserEntity> findAll() throws Exception {
		List<UserEntity> list = new ArrayList<>();
		userRepository.findAll().iterator().forEachRemaining(list::add);
		return list;
	}
	
	private UserEntity convertDtoToEntit(UserEntity user) {
		UserEntity entity = new UserEntity();
		if (user != null) {
			entity.setId(user.getId());
			entity.setFirst_name(user.getFirst_name());
			entity.setLast_name(user.getLast_name());
			entity.setUsername(user.getUsername());
			entity.setPassword(user.getPassword());
			entity.setCitizen(user.getCitizen());
			entity.setEmail(user.getEmail());
			entity.setTel(user.getTel());
			entity.setGender(user.getGender());
			entity.setRole(user.getRole());
			entity.setStatus(user.getStatus());
			entity.setRoleEntity(user.getRoleEntity());
		}
		return entity;
	}

	@Override
	public void delete(long id) throws Exception {
		userRepository.deleteById(id);
	}

	@Override
	public UserEntity findUserByUsername(String username) throws Exception {
		UserEntity entity = userRepository.findByUsername(username);
		if (entity == null) {
			throw new RuntimeException("username is Not found " + username);
		}
		return entity;
	}
}
