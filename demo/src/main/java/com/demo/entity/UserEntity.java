package com.demo.entity;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;

@Entity(name="users")
public class UserEntity implements Serializable{
	
	private static final long serialVersionUID = -7390009509615135727L;
	
	@Id
	@GeneratedValue
	//This id can't be public so we have created userId which is public
	private long id;
  
	//To generate secure public userId, we have written a method generateUserId in Utils.class 
	//which can be used by user to get details & this userId can be public
	@Column(nullable=false)
	private String userId; 
    
    @Column(nullable=false,length=50)
    private String firstName;
    
    @Column(nullable=false, length=50)
    private String lastName;
    
    @Column(nullable=false, length=50, unique=true)
    private String email;
    
    @Column(nullable=false)
	private String password;

    private String encryptedPassword;
    
	private String emailVerificationToken;
	
	@Column(nullable=false)
	private Boolean emailVerificationStatus = false; //Setting default value as false

	@OneToMany(mappedBy = "userDetails", cascade = CascadeType.ALL) 
	private List<AddressEntity> addresses;

	//We use CascadeType.PERSIST bcuz if we want to delete user we don't want to delete the data from roles table
	//We use fetch=FetchType.EAGER bcuz if we fetch particular user details we want it roles to be fetched at the same time
	@ManyToMany(cascade = {CascadeType.PERSIST},fetch=FetchType.EAGER)
	@JoinTable(name="users_roles",
	           joinColumns = @JoinColumn(name="users_id",referencedColumnName = "id"),
	           inverseJoinColumns = @JoinColumn(name="roles_id", referencedColumnName = "id"))
	private Collection<RoleEntity> roles;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEncryptedPassword() {
		return encryptedPassword;
	}

	public void setEncryptedPassword(String encryptedPassword) {
		this.encryptedPassword = encryptedPassword;
	}

	public String getEmailVerificationToken() {
		return emailVerificationToken;
	}

	public void setEmailVerificationToken(String emailVerificationToken) {
		this.emailVerificationToken = emailVerificationToken;
	}

	public Boolean getEmailVerificationStatus() {
		return emailVerificationStatus;
	}

	public void setEmailVerificationStatus(Boolean emailVerificationStatus) {
		this.emailVerificationStatus = emailVerificationStatus;
	}

	public List<AddressEntity> getAddresses() {
		return addresses;
	}

	public void setAddresses(List<AddressEntity> addresses) {
		this.addresses = addresses;
	}

	public Collection<RoleEntity> getRoles() {
		return roles;
	}

	public void setRoles(Collection<RoleEntity> roles) {
		this.roles = roles;
	}
	
	
}
