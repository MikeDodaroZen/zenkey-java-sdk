package com.zenkey.service;

import com.zenkey.domain.AuthorizationOidcResponse;

public interface AuthorizationHandler {

    AuthorizationOidcResponse getAuthorization(String clientId, String mccmnc, String loginHintToken, String redirectUri);

    AuthorizationOidcResponse getAuthorizationToken(String clientId, String tokenEndPoint, String userInfoEndpoint, String mccmnc, String code, String clientKeyPairs, String keyPair);

    AuthorizationOidcResponse getAuthorizationTokenOptimized(String clientId, String mccmnc, String code, String clientKeyPairs, String keyPair);

    AuthorizationOidcResponse getAuthorizationServerInitiated(String clientId, String sub, String clientKeyPairs, String keyPair);
}
