package com.dtb.springsecurityoauthonetimetoken.service.impl;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class InMemoryUserDetailsServiceTest {
	
	static final String USERNAME = "dattebayorob";
	
	@Mock PasswordEncoder passwordEncoder;
	
	InMemoryUserDetailsService inMemoryUserDetailsService;
	
	@BeforeEach
	public void beforeEach() {
		when(passwordEncoder.encode(Mockito.anyString())).thenAnswer(answer -> answer.getArgument(0));
		inMemoryUserDetailsService = new InMemoryUserDetailsService(passwordEncoder);
	}
	
	@Test
	@DisplayName("Should retrieve a username by id in memory")
	public void shouldRetrieveAUsernameById() {
		UserDetails user = inMemoryUserDetailsService.loadUserByUsername(USERNAME);
		assertNotNull(user);
		assertEquals(USERNAME, user.getUsername());
	}
	
	@Test
	@DisplayName("Should throw exception if no user had been found ")
	public void shouldThrowExceptionIfNoUserHadBeenFound() {
		assertThatThrownBy(() -> inMemoryUserDetailsService.loadUserByUsername("NONONO"))
			.isExactlyInstanceOf(UsernameNotFoundException.class);
	}
}
