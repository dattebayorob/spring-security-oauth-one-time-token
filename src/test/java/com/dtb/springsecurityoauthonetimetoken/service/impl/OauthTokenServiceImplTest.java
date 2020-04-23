package com.dtb.springsecurityoauthonetimetoken.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;

@ExtendWith(MockitoExtension.class)
public class OauthTokenServiceImplTest {
	
	static final String AUDIENCE = "apimock";
	static final String SCOPE = "mock:write";
	
	@Mock TokenStore tokenStore;
	
	OauthTokenServiceImpl oauthTokenService;
	
	@BeforeEach
	public void beforeEach() {
		oauthTokenService = spy(new OauthTokenServiceImpl(tokenStore));
	}

	@Test
	@DisplayName("Should consume the token and righ after deleting it")
	public void shouldConsumeTheTokenAndRightAfterDeletingIt() {
		doNothing().when(tokenStore).storeAccessToken(Mockito.any(OAuth2AccessToken.class), Mockito.any(OAuth2Authentication.class));
		doNothing().when(tokenStore).removeAccessToken(Mockito.any(OAuth2AccessToken.class));
		
		oauthTokenService.oneTimeToken(
				token -> { 
					assertThat(token).isNotEmpty();
				}, AUDIENCE, SCOPE
		);
		
		verify(tokenStore, times(1)).storeAccessToken(Mockito.any(OAuth2AccessToken.class), Mockito.any(OAuth2Authentication.class));
		verify(tokenStore, times(1)).removeAccessToken(Mockito.any(OAuth2AccessToken.class));
		
	}
	
	@Test
	@DisplayName("Should consume the token and return the result after deleting it")
	public void shouldConsumeTheTokenAndReturnTheResultAfterDeletingIt() {
		doNothing().when(tokenStore).storeAccessToken(Mockito.any(OAuth2AccessToken.class), Mockito.any(OAuth2Authentication.class));
		doNothing().when(tokenStore).removeAccessToken(Mockito.any(OAuth2AccessToken.class));
		
		Map<String, String> params =  oauthTokenService.oneTimeToken(
				token -> {
					Map<String, String> map = new HashMap<>();
					map.put("token", token);
					return map;
				}, AUDIENCE, SCOPE
		);
		
		assertThat(params.containsKey("token")).isTrue();
		
		verify(tokenStore, times(1)).storeAccessToken(Mockito.any(OAuth2AccessToken.class), Mockito.any(OAuth2Authentication.class));
		verify(tokenStore, times(1)).removeAccessToken(Mockito.any(OAuth2AccessToken.class));
		
	}
	
	@Test
	@DisplayName("Should remove the token if an exception is thrown")
	public void shouldRemoveTheTokenIfAnExceptionIsThrown() {
		doNothing().when(tokenStore).storeAccessToken(Mockito.any(OAuth2AccessToken.class), Mockito.any(OAuth2Authentication.class));
		doNothing().when(tokenStore).removeAccessToken(Mockito.any(OAuth2AccessToken.class));
		
		assertThatThrownBy( () -> 
			oauthTokenService.oneTimeToken(
				token -> {
					if(!token.isEmpty()) {
						throw new RuntimeException(token);						
					}
					return;
				}, AUDIENCE, SCOPE
		)).isInstanceOf(RuntimeException.class);
		
		verify(tokenStore, times(1)).storeAccessToken(Mockito.any(OAuth2AccessToken.class), Mockito.any(OAuth2Authentication.class));
		verify(tokenStore, times(1)).removeAccessToken(Mockito.any(OAuth2AccessToken.class));
		
	}

}
