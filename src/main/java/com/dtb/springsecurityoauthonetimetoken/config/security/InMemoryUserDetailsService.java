package com.dtb.springsecurityoauthonetimetoken.config.security;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class InMemoryUserDetailsService implements UserDetailsService{
	private final Set<UserDetails> users;
	
	public InMemoryUserDetailsService( PasswordEncoder passwordEncoder ) {
		users = new HashSet<>(Arrays.asList(
				User
					.withUsername("dattebayorob")
					.password(passwordEncoder.encode("password"))
					.roles("ADMIN")
					.authorities("BLA","BLE")
				.build()
		));
	}
	

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return users
					.stream()
					.filter( user -> user.getUsername().equals(username) )
					.findFirst()
					.orElseThrow( () -> new UsernameNotFoundException("Not Found") );
	}

}
