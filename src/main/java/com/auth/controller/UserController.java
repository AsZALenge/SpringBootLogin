package com.auth.controller;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.auth.entity.UserEntity;
import com.auth.service.UserService;

@RestController
public class UserController {
	
	@Autowired
    private UserService userService;
	
	@GetMapping("/user/all")
    public ResponseEntity<List<UserEntity>> listUser() throws Exception {		
        return new ResponseEntity<List<UserEntity>>(userService.findAll(), HttpStatus.OK);
    }
	
	@GetMapping("/user/{username}")
	@ResponseBody
    public ResponseEntity<UserEntity> getUser(@PathVariable(value = "username") String username) throws Exception {		
        return new ResponseEntity<UserEntity>(userService.findUserByUsername(username), HttpStatus.OK);
    }

    @PostMapping("/user/save")
    @ResponseBody
    public ResponseEntity<UserEntity> create(@Valid @RequestBody UserEntity user) throws Exception{
        return new ResponseEntity<UserEntity>(userService.save(user), HttpStatus.CREATED);
    }
    
    @PostMapping("/user/update")
	public ResponseEntity<UserEntity> updateUser(@RequestBody UserEntity user) throws Exception {
		if (user != null) {
			userService.updateUser(user);
		}
		return new ResponseEntity<UserEntity>(user, HttpStatus.OK);
	}

    @DeleteMapping("/user/{id}")
    public ResponseEntity<String> delete(@PathVariable(value = "id") Long id) throws Exception{
        userService.delete(id);
        return new ResponseEntity<String>("success", HttpStatus.OK);
    }

}
