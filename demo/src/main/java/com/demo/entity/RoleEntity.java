package com.demo.entity;

import java.io.Serializable;
import java.util.Collection;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

@Entity
@Table(name="roles")
public class RoleEntity implements Serializable {

	private static final long serialVersionUID = -4825056418249073408L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private long id;
	
	@Column(nullable = false, length = 20)
	private String name;
	
	@ManyToMany(mappedBy = "roles")
	private Collection<UserEntity> users;
	
	
	//We use CascadeType.PERSIST bcuz if we want to delete user we don't want to delete the data from roles table
	//We use fetch=FetchType.EAGER bcuz if we fetch particular user details we want it roles to be fetched at the same time
	@ManyToMany(cascade = {CascadeType.PERSIST},fetch=FetchType.EAGER)
	@JoinTable(name="roles_authorities",
    joinColumns = @JoinColumn(name="roles_id",referencedColumnName = "id"),
    inverseJoinColumns = @JoinColumn(name="authorities_id", referencedColumnName = "id"))
	private Collection<AuthorityEntity> authorities;


	public RoleEntity() {
      //No arg Constructor
	}
	
	public RoleEntity(String name) {
		this.name= name;
	}


	public long getId() {
		return id;
	}


	public void setId(long id) {
		this.id = id;
	}


	public String getName() {
		return name;
	}


	public void setName(String name) {
		this.name = name;
	}


	public Collection<UserEntity> getUsers() {
		return users;
	}


	public void setUsers(Collection<UserEntity> users) {
		this.users = users;
	}


	public Collection<AuthorityEntity> getAuthorities() {
		return authorities;
	}


	public void setAuthorities(Collection<AuthorityEntity> authorities) {
		this.authorities = authorities;
	}
		
}
