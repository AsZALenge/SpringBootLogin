package com.auth.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

@Entity
@Table(name = "oauth_role")
public class RoleEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "id")
	private Integer id;

	@Column(name = "role_name")
	private String role_name;

	@Column(name = "role_status")
	private String role_status;

	@OneToMany(mappedBy = "roleEntity", cascade = CascadeType.REFRESH)
	private List<UserEntity> userEntities;

	public RoleEntity() {
		super();
	}

	public RoleEntity(Integer id, String role_name, String role_status, List<UserEntity> userEntities) {
		super();
		this.id = id;
		this.role_name = role_name;
		this.role_status = role_status;
		this.userEntities = userEntities;
	}

	public String getRole_status() {
		return role_status;
	}

	public void setRole_status(String role_status) {
		this.role_status = role_status;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getRole_name() {
		return role_name;
	}

	public void setRole_name(String role_name) {
		this.role_name = role_name;
	}

	public List<UserEntity> getUserEntities() {
		return userEntities;
	}

	public void setUserEntities(List<UserEntity> userEntities) {
		this.userEntities = userEntities;
	}

}
