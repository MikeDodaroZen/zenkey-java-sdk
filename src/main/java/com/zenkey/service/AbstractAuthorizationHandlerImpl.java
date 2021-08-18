package com.zenkey.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.zenkey.domain.AuthorizationOidcResponse;
import com.zenkey.domain.AuthorizationStatus;
import com.zenkey.domain.OidcUrlInfo;

public class AbstractAuthorizationHandlerImpl {

    protected AuthorizationOidcResponse constructAuthorizationOidcResponse(Boolean isSuccess, String message, String sub) {

        AuthorizationOidcResponse authorizationOidcResponse = new AuthorizationOidcResponse();

        authorizationOidcResponse.setIsSuccess(isSuccess);
        authorizationOidcResponse.setMessage(message);
        authorizationOidcResponse.setStatus(AuthorizationStatus.SUCCESSFUL.name());
        if (sub != null) {
            authorizationOidcResponse.setSub(sub);
        }
        authorizationOidcResponse.setIsCarrier(true);
        authorizationOidcResponse.setIsRedirectForAuthorization(false);

        return authorizationOidcResponse;
    }

    protected AuthorizationOidcResponse constructAuthorizationOidcResponse(Boolean isSuccess, String message, String status, JsonNode data) {

        AuthorizationOidcResponse authorizationOidcResponse = new AuthorizationOidcResponse();

        authorizationOidcResponse.setIsSuccess(isSuccess);
        authorizationOidcResponse.setMessage(message);
        authorizationOidcResponse.setStatus(status);
        if (data != null) {
            authorizationOidcResponse.setData(data);
        }

        return authorizationOidcResponse;
    }

    protected AuthorizationOidcResponse constructAuthorizationOidcResponse(Boolean isSuccess, String message, String status, JsonNode data, Boolean isCarrier) {

        AuthorizationOidcResponse authorizationOidcResponse = new AuthorizationOidcResponse();

        authorizationOidcResponse.setIsSuccess(isSuccess);
        authorizationOidcResponse.setMessage(message);
        authorizationOidcResponse.setStatus(status);
        if (data != null) {
            authorizationOidcResponse.setData(data);
        }
        if (isCarrier != null) {
            authorizationOidcResponse.setIsCarrier(isCarrier);
        } else {
            authorizationOidcResponse.setIsCarrier(true);
        }

        return authorizationOidcResponse;
    }

    protected AuthorizationOidcResponse constructAuthorizationOidcResponse(Boolean isSuccess, String message, String status, JsonNode data, Boolean isCarrier, Boolean isRedirectForAuthorization, OidcUrlInfo oidcUrlInfo) {

        AuthorizationOidcResponse authorizationOidcResponse = new AuthorizationOidcResponse();

        authorizationOidcResponse.setIsSuccess(isSuccess);
        authorizationOidcResponse.setMessage(message);
        authorizationOidcResponse.setStatus(status);
        if (data != null) {
            authorizationOidcResponse.setData(data);
        }
        if (isCarrier != null) {
            authorizationOidcResponse.setIsCarrier(isCarrier);
        } else {
            authorizationOidcResponse.setIsCarrier(true);
        }
        if (isRedirectForAuthorization != null) {
            authorizationOidcResponse.setIsRedirectForAuthorization(isRedirectForAuthorization);
        } else {
            authorizationOidcResponse.setIsRedirectForAuthorization(false);
        }
        if (oidcUrlInfo != null) {
            authorizationOidcResponse.setOidcUrlInfo(oidcUrlInfo);
        }

        return authorizationOidcResponse;
    }
}

