package com.zenkey.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zenkey.domain.AuthorizationOidcResponse;
import com.zenkey.domain.AuthorizationStatus;
import com.zenkey.domain.OidcUrlInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class AbstractAuthorizationHandlerImpl {

    protected static final Logger log = LoggerFactory.getLogger(AuthorizationHandlerImpl.class);

    protected static final String BASE_URL = "baseUrl";
    protected static final String RESPONSE_TYPE = "response_type";
    protected static final String ASYNC_TOKEN = "async_token";
    protected static final String HEADER_TYPE = "header_type";
    protected static final String HEADER_TYPE_APPLICATION_JSON = "application_json";
    protected static final String REDIRECT_URI = "redirect_uri";
    protected static final String NOTIFICATION_URI = "notification_uri";
    protected static final String IAT = "iat";
    protected static final String SUB = "sub";
    protected static final String EXP = "exp";
    protected static final String ISS = "iss";
    protected static final String AUD = "aud";
    protected static final String EXPIRES_IN = "expires_in";
    protected static final int EXPIRES_IN_VALUE = 3000;
    protected static final String SCOPE = "scope";
    protected static final String SCOPE_OPENID = "openid";
    protected static final String CORRELATION_ID = "correlation_id";
    protected static final String CLIENT_ID = "client_id";
    protected static final String ACR_VALUES = "acr_values";
    protected static final String ACR_VALUES_A3 = "a3";
    protected static final String CLIENT_NOTIFICATION_TOKEN = "client_notification_token";
    protected static final String LOGIN_HINT = "login_hint";
    protected static final String LOGIN_HINT_TOKEN = "login_hint_token";
    protected static final String STATE = "state";
    protected static final String CONTEXT = "context";
    protected static final String NONCE = "nonce";
    protected static final String JTI = "jti";
    protected static final String SDK_VERSION = "sdk_version";
    protected static final String PROMPT = "prompt";
    protected static final String OPTIONS = "options";
    protected static final String REFERRED_BINDING = "referred_binding";
    protected static final String GRANT_TYPE = "grant_type";
    protected static final String CODE = "code";
    protected static final String CODE_VERIFIER = "code_verifier";
    protected static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    protected static final String CLIENT_ASSERTION = "client_assertion";
    protected static final String REQUEST = "request";
    protected static final String CARRIER_AUTH_ENDPOINT = "carrier_auth_endpoint";
    protected static final String TOKEN_ENDPOINT = "token_endpoint";
    protected static final String USERINFO_ENDPOINT = "userinfo_endpoint";
    protected static final String OPTIMIZED_DISCOVERY_URL = "https://auth.myzenkey.com/v1/auth";
    protected static final String DISCOVERY_ISSUER_URL = "https://discoveryissuer.xcijv.com/.well-known/openid_configuration";
    protected static final String MNO_STATE_VALUE = "login";

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

    protected AuthorizationOidcResponse constructAuthorizationOidcResponse(Boolean isSuccess, String message, String status, JsonNode data, Boolean isCarrier, Boolean isServerInitiated, Boolean isServerInitiatedError) {
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
        if (isServerInitiated != null) {
            authorizationOidcResponse.setIsServerInitiated(isServerInitiated);
        } else {
            authorizationOidcResponse.setIsServerInitiated(false);
        }
        if (isServerInitiatedError != null) {
            authorizationOidcResponse.setIsServerInitiatedError(isServerInitiatedError);
        } else {
            authorizationOidcResponse.setIsServerInitiatedError(false);
        }

        return authorizationOidcResponse;
    }

    protected String convertListToSpaceDelimitedString(List<String> list) {

        String joinedString = String.join(" ", list);
        log.info("joinedString: {}", joinedString);
        return joinedString;
    }

    protected JsonNode buildJsonNodeForOptimizedDiscoveryRedirectUrl(String optimizedRedirectUrl) {

        log.info("Entering buildJsonNodeForOptimizedDiscoveryRedirectUrl");
        JsonNode jsonNode = null;
        ObjectMapper mapper = new ObjectMapper(new JsonFactory());

        org.json.JSONObject jo = new org.json.JSONObject();
        jo.put("optimized_discovery_url", optimizedRedirectUrl);
        log.info("JSON Object: {}", jo.toString());
        try {
            jsonNode = mapper.readTree(jo.toString());
        } catch (Exception ex) {
            log.error("Error creating JSON object with optimized redirect URL");
        }
        log.info("JSON Node: {}", jsonNode.toString());
        log.info("Leaving buildJsonNodeForOptimizedDiscoveryRedirectUrl");
        return jsonNode;
    }
}

