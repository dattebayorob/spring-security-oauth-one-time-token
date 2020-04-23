package com.dtb.springsecurityoauthonetimetoken.service.impl;

import static java.util.stream.Collectors.joining;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import com.dtb.springsecurityoauthonetimetoken.service.OauthTokenService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OauthTokenServiceImpl implements OauthTokenService{
	protected static final String RESOURCE_ID = "oauth"; 
	private static final String CLIENT_CREDENTIALS = "client_credentials"; 
	private static final Integer ACCESS_TOKEN_TTL_IN_SECONDS = 300;

	private final TokenStore tokenStore;
	
	@Override
	public void oneTimeToken(Consumer<String> callBackWithToken, String aud, String ... scopes) {
		oneTimeToken( 
				token -> {
					callBackWithToken.accept(token);
					return token;
				}, aud, scopes
		);
	}
	
	@Override
	public <T> T oneTimeToken(Function<String, T> callBackWithToken, String aud, String ... scopes) {
		OAuth2AccessToken token = createAccessToken(aud, scopes);
		try {
			T response = callBackWithToken.apply(token.getValue());			
			tokenStore.removeAccessToken(token);
			return response;
		}catch(Exception e) {
			tokenStore.removeAccessToken(token);
			throw e;
		}
	}
	
	protected OAuth2AccessToken createAccessToken(String aud, String ... scopes) {
		Set<String> scope = Stream.of(scopes).collect(Collectors.toSet());
		
		TokenRequest tokenRequest = new TokenRequest(
				authorizationParameters(scope.stream().collect(joining(" "))), RESOURCE_ID, scope, CLIENT_CREDENTIALS
		);
		OAuth2Authentication authentication = new OAuth2Authentication(
				tokenRequest.createOAuth2Request(getClientDetails(aud, scope)), null
		);
		
		OAuth2AccessToken token = createAccessToken(authentication, null);
		tokenStore.storeAccessToken(token, authentication);
		
		return token;
	}
	
	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());
		token.setExpiration(new Date(System.currentTimeMillis() + (ACCESS_TOKEN_TTL_IN_SECONDS * 1000L)));
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getOAuth2Request().getScope());

		return token;
	}
	
	private Map<String, String> authorizationParameters(String scope) {
		Map<String, String> authorizationParameters = new HashMap<>();
        authorizationParameters.put("scope", scope);
        authorizationParameters.put("grant_type", CLIENT_CREDENTIALS);
        return authorizationParameters;
	}
	
	private ClientDetails getClientDetails(String aud, Set<String> scopes) {
		return new BaseClientDetails(
				RESOURCE_ID, aud, scopes.stream().collect(joining(" ")), "", ""
		);
	}

}
