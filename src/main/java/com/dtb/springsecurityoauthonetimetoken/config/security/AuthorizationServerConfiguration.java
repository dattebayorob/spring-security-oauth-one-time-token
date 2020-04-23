package com.dtb.springsecurityoauthonetimetoken.config.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableAuthorizationServer
@RequiredArgsConstructor
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter{
	private final TokenStore tokenStore;
	private final UserDetailsService userDetailsService;
	private final AuthenticationManager authenticationManager;
	private final PasswordEncoder rawPasswordEncoder;
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.tokenStore(tokenStore)
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService);
	}
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("webapp")
				.secret(rawPasswordEncoder.encode("webapp"))
				.authorizedGrantTypes("authorization_code")
				.resourceIds("resourceserver")
				.redirectUris("http://localhost:3000")
				.scopes("openapi")
				.accessTokenValiditySeconds(300)
			.and()
				.withClient("resourceserver")
				.secret(rawPasswordEncoder.encode("resourceserver"))
				.authorizedGrantTypes("client_credentials")
				.accessTokenValiditySeconds(300)
				.autoApprove(true);
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.passwordEncoder(rawPasswordEncoder);
	}
}
