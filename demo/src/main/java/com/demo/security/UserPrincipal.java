package com.demo.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.demo.entity.AuthorityEntity;
import com.demo.entity.RoleEntity;
import com.demo.entity.UserEntity;

public class UserPrincipal implements UserDetails {

	private static final long serialVersionUID = -4394551213064613075L;
	
	private UserEntity userEntity;
	
	public UserPrincipal() {
		//No arg Constructor
	}
	
	public UserPrincipal(UserEntity userEntity) {
		this.userEntity=userEntity;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		List<GrantedAuthority> authorities = new ArrayList<>();
		List<AuthorityEntity> authorityEntities = new ArrayList<>();
		
		//Get user Roles
		Collection<RoleEntity> roles= userEntity.getRoles();
		
		if(roles == null) return authorities;
		
		roles.forEach((role)-> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
			authorityEntities.addAll(role.getAuthorities());
		});
		
		authorityEntities.forEach((authorityEntity)->{
			authorities.add(new SimpleGrantedAuthority(authorityEntity.getName()));
		});		
		
		return authorities;
	}

	@Override
	public String getPassword() {
		return this.userEntity.getEncryptedPassword();
	}

	@Override
	public String getUsername() {
		return this.userEntity.getEmail();
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}

}
