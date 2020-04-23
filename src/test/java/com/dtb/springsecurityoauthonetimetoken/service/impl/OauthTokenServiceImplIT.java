package com.dtb.springsecurityoauthonetimetoken.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.function.Function;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.dtb.springsecurityoauthonetimetoken.service.OauthTokenService;

@SpringBootTest
@ExtendWith(SpringExtension.class)
class OauthTokenServiceImplIT {
	static final String AUDIENCE_CLIENT_ID = "resourceserver";
	static final String SCOPE = "mock:read";
	
	@Autowired TokenStore tokenStore;
	@Autowired OauthTokenService oauthTokenService;
	
	@Test
	@DisplayName("Should read a access token created only for this function")
	public void shouldReadAAccessTokenCreatedOnlyForThisFunction() {
		
		OAuth2AccessToken  storedToken = oauthTokenService.oneTimeToken(introspect(), AUDIENCE_CLIENT_ID, SCOPE);
		
		assertNotNull(storedToken);
		assertThat(storedToken.getScope()).contains(SCOPE);		
	}
	
	Function<String, OAuth2AccessToken> introspect() {
		return token -> {
			OAuth2AccessToken storedToken = tokenStore.readAccessToken(token);
			storedToken.getScope();
			return storedToken;
		};
	}

}
