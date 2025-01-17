package com.demo.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.demo.entity.UserEntity;
import com.demo.repo.UserRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class AuthorizationFilter extends BasicAuthenticationFilter{
	
	  private final UserRepository userRepository;

	  public AuthorizationFilter(AuthenticationManager authManager, UserRepository userRepository) {
	        super(authManager);
	        this.userRepository=userRepository;
	     }
	  
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
				throws IOException, ServletException {
			String header = request.getHeader(SecurityConstants.HEADER_STRING);
			if(header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
				chain.doFilter(request, response);
				return;
			}
			UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(request, response);
			
		}
	    
	    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
	       
	       String authorizationHeader = request.getHeader(SecurityConstants.HEADER_STRING);
	       if (authorizationHeader == null) {
	           return null;
	       }
	       String token = authorizationHeader.replace(SecurityConstants.TOKEN_PREFIX, "");
	       byte[] secretKeyBytes = Base64.getEncoder().encode(SecurityConstants.getTokenSecret().getBytes());
	       SecretKey secretKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
	       JwtParser jwtParser = Jwts.parserBuilder()
	               .setSigningKey(secretKey)
	               .build();
	       Jwt<Header, Claims> jwt = jwtParser.parse(token);
	       String user = jwt.getBody().getSubject();
	       
	       if(user != null) {
	    	   UserEntity userEntity = userRepository.findByEmail(user);
	    	   UserPrincipal userPrincipal = new UserPrincipal(userEntity);
	           return new UsernamePasswordAuthenticationToken(user, null, userPrincipal.getAuthorities());       
	       }
	       return null;
	   }	
}
