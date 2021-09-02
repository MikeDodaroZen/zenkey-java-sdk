package com.zenkey.service;

import com.zenkey.domain.AuthorizationOidcResponse;

import java.util.List;

public interface AuthorizationHandler {

    AuthorizationOidcResponse getAuthorization(String clientId, String mccmnc, String loginHintToken, String redirectUri);

    AuthorizationOidcResponse getAuthorizationOptimized(String clientId, String mccmnc, String loginHintToken, String redirectUri, List scopes);

    AuthorizationOidcResponse getAuthorizationToken(String clientId, String tokenEndPoint, String userInfoEndpoint, String mccmnc, String code, String clientKeyPairs, String keyPair);

    AuthorizationOidcResponse getAuthorizationTokenOptimized(String clientId, String mccmnc, String code, String clientKeyPairs, String keyPair);

    AuthorizationOidcResponse getAuthorizationServerInitiated(String clientId, String sub, String clientKeyPairs, String keyPair);
}
