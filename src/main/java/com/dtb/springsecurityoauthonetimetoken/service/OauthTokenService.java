package com.dtb.springsecurityoauthonetimetoken.service;

import java.util.function.Consumer;
import java.util.function.Function;

public interface OauthTokenService {
	public void oneTimeToken(Consumer<String> callBackWithToken, String aud, String ...scopes);
	public <T>T oneTimeToken(Function<String, T> callBackWithToken, String aud, String ... scopes);
}
