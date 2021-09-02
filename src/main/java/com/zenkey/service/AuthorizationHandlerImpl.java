package com.zenkey.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.zenkey.exception.OauthException;
import com.zenkey.domain.*;
import net.minidev.json.JSONObject;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;

public class AuthorizationHandlerImpl extends AbstractAuthorizationHandlerImpl implements AuthorizationHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationHandlerImpl.class);

    RestTemplate restTemplate = new RestTemplate();

    /**
     * Attempt or re-attempt discovery-issuer.
     * @param clientId
     * @param mccmnc
     * @param loginHintToken
     * @param redirectUri
     * @return
     */
    public AuthorizationOidcResponse getAuthorization(String clientId, String mccmnc, String loginHintToken, String redirectUri) {
        log.info("===> Calling getAuthorization");
        log.info("===> loginTokenHint: {}", loginHintToken );
        log.info("===> mccmnc: {}", mccmnc);

        AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

        if (mccmnc == null || mccmnc.trim().length() == 0) {
            return constructAuthorizationOidcResponse(false, "Authorization failed.  Carrier was not found", AuthorizationStatus.FAILED.name(), null, false);
        }
        if (loginHintToken == null || loginHintToken.trim().length() == 0) {
            return constructAuthorizationOidcResponse(false, "Authorization failed.  A login hint token is required for authorization", AuthorizationStatus.FAILED.name(), null, false);
        }

        log.info("===> Creating new DiscoveryIssuerServiceImpl object");
        DiscoveryIssuerService discoveryIssuerService = new DiscoveryIssuerServiceImpl();
        ResponseEntity<String> responseEntityAuth = null;
        log.info("===> About to get authorization response");
        try {
            responseEntityAuth = discoveryIssuerService.callDiscoveryIssuerService(clientId, mccmnc, null, null);
            log.info("===> Successfully got authorization response");
            log.info("======================= Completed Step 1 or 3 - Discovery Issuer:  Received OIDC Config");
        }  catch (Exception ex) {
            String returnMessage = String.format("Authorization Failed: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("===> Authorization response is {}", responseEntityAuth.getBody());

        if (responseEntityAuth.getBody() == null) {
            String parseAuthorizationUrlError = "Not able to parse authorization URL from Oidc config";
            log.error(parseAuthorizationUrlError);
            return constructAuthorizationOidcResponse(false, parseAuthorizationUrlError, AuthorizationStatus.FAILED.name(), null);
        }

        OidcUrlInfo oidcUrlInfo = discoveryIssuerService.buildOidcUrlInfo(responseEntityAuth.getBody());
        if (oidcUrlInfo == null) {
            return constructAuthorizationOidcResponse(false, "Error parsing authorization URL from Oidc config", AuthorizationStatus.FAILED.name(), null);
        } else {
            log.info("===> OidcUrlInfo: " + oidcUrlInfo.toString());

            String redirectForAuthorizationMessage = "Redirect for authorization";
            return constructAuthorizationOidcResponse(false, "Returning OIDC Url Info", AuthorizationStatus.SUCCESSFUL.name(), null, true, true, oidcUrlInfo);
        }
    }

    /**
     * Attempt or re-attempt discovery-issuer.
     * @param clientId
     * @param mccmnc
     * @param loginHintToken
     * @param redirectUri
     * @param scopes
     * @return
     */
    public AuthorizationOidcResponse getAuthorizationOptimized(String clientId, String mccmnc, String loginHintToken, String redirectUri, List scopes) {
        log.info("===> Calling getAuthorizationOptimized");
        log.info("===> loginTokenHint: {}", loginHintToken );
        log.info("===> mccmnc: {}", mccmnc);

        AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

        if (mccmnc == null || mccmnc.trim().length() == 0) {
            String redirectBackToCustomerAppUrl = null;
            try {
                redirectBackToCustomerAppUrl = buildOptimizedDiscoveryRedirectUrl(scopes, redirectUri, clientId);
            } catch (Exception ex) {
                return constructAuthorizationOidcResponse(false, String.format("Error creating redirect URL back to customer's app: %s", ex.getMessage()), AuthorizationStatus.FAILED.name(), null);
            }
            JsonNode jsonNode = buildJsonNodeForOptimizedDiscoveryRedirectUrl(redirectBackToCustomerAppUrl);
            log.info("jsonNode: {}", jsonNode);
            return constructAuthorizationOidcResponse(false, "Authorization failed.  Carrier was not found", AuthorizationStatus.FAILED.name(), jsonNode, false);
        }
        if (loginHintToken == null || loginHintToken.trim().length() == 0) {
            return constructAuthorizationOidcResponse(false, "Authorization failed.  A login hint token is required for authorization", AuthorizationStatus.FAILED.name(), null, false);
        }

        log.info("===> Creating new DiscoveryIssuerServiceImpl object");
        DiscoveryIssuerService discoveryIssuerService = new DiscoveryIssuerServiceImpl();
        ResponseEntity<String> responseEntityAuth = null;
        log.info("===> About to get authorization response");
        try {
            responseEntityAuth = discoveryIssuerService.callDiscoveryIssuerService(clientId, mccmnc, null, null);
            log.info("===> Successfully got authorization response");
            log.info("======================= Completed Step 1 or 3 - Discovery Issuer:  Received OIDC Config");
        }  catch (Exception ex) {
            String returnMessage = String.format("Authorization Failed: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("===> Authorization response is {}", responseEntityAuth.getBody());

        if (responseEntityAuth.getBody() == null) {
            String parseAuthorizationUrlError = "Not able to parse authorization URL from Oidc config";
            log.error(parseAuthorizationUrlError);
            return constructAuthorizationOidcResponse(false, parseAuthorizationUrlError, AuthorizationStatus.FAILED.name(), null);
        }

        OidcUrlInfo oidcUrlInfo = discoveryIssuerService.buildOidcUrlInfo(responseEntityAuth.getBody());
        if (oidcUrlInfo == null) {
            return constructAuthorizationOidcResponse(false, "Error parsing authorization URL from Oidc config", AuthorizationStatus.FAILED.name(), null);
        } else {
            log.info("===> OidcUrlInfo: " + oidcUrlInfo.toString());

            String redirectForAuthorizationMessage = "Redirect for authorization";
            return constructAuthorizationOidcResponse(false, "Returning OIDC Url Info", AuthorizationStatus.SUCCESSFUL.name(), null, true, true, oidcUrlInfo);
        }
    }

    public AuthorizationOidcResponse getAuthorizationToken(String clientId, String tokenEndPoint, String userInfoEndpoint, String mccmnc, String code, String clientKeyPairs, String keyPair) {
        log.info("Entering getAuthorizationToken");
        AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

        String signedAssertion = "";
        String tokenResponse = "";

        try {
            signedAssertion = getSignedAssertion(clientId, tokenEndPoint, mccmnc, code, clientKeyPairs, keyPair);
        } catch (Exception ex) {
            String returnMessage = String.format("===> Get Authorization Token Failed: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }

        TokenRequestBody tokenRequestBody = createTokenRequestBody(clientId, mccmnc, signedAssertion, code);

        try {
            tokenResponse = getTokenV2(tokenRequestBody, tokenEndPoint);
            log.info("Just got token response from getTokenV2: {}", tokenResponse);
        } catch (OauthException ex) {
            String returnedMessage = String.format("Error getting tokenV2: OAuthException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        } catch (Exception ex) {
            String returnedMessage = String.format("Error getting tokenV2: Exception: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("Token response from getTokenV2: {}", tokenResponse);

        ObjectMapper mapper = new ObjectMapper(new JsonFactory());
        JsonNode jsonNode = null;
        try {
            jsonNode = mapper.readTree(tokenResponse);
        } catch (JsonMappingException ex) {
            String returnedMessage = String.format("Error JSON parsing tokenResponse: JsonMappingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        } catch (JsonProcessingException ex) {
            String returnedMessage = String.format("Error JSON parsing tokenResponse: JsonProcessingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }
        String accessToken = ((ObjectNode) jsonNode).get("access_token").asText();
        log.info("===> Parsed accessToken: {}", accessToken);

        org.json.JSONObject userInfoResponse = null;

        try {
            userInfoResponse = getUserInfo(userInfoEndpoint, accessToken);
        } catch (Exception ex) {
            String returnedMessage = String.format("Error with getUserInfo: Exception: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("userInfoResponse: {}", userInfoResponse);

        if (userInfoResponse == null) {
            String returnedMessage = "User Info is empty.  This is considered abnormal, therefore an error";
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }

        JsonNode userInfoJson = null;

        mapper = new ObjectMapper(new JsonFactory());
        try {
            userInfoJson = mapper.readTree(userInfoResponse.toString());
        } catch (JsonMappingException ex) {
            String returnedMessage = String.format("Error converting JSONObject to JsonNode: JsonMappingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        } catch (JsonProcessingException ex) {
            String returnedMessage = String.format("Error converting JSONObject to JsonNode: JsonProcessingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }

        authorizationResponse = constructAuthorizationOidcResponse(true, "Get User Info Was Successful", AuthorizationStatus.SUCCESSFUL.name(), userInfoJson);
        log.info("Leaving getAuthorizationToken");
        return authorizationResponse;
    }

    public AuthorizationOidcResponse getAuthorizationTokenOptimized(String clientId, String mccmnc, String code, String clientKeyPairs, String keyPair) {
        log.info("Entering getAuthorizationToken");
        AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

        if (mccmnc == null || mccmnc.trim().length() == 0) {
            return constructAuthorizationOidcResponse(false, "Authorization failed.  Carrier was not found", AuthorizationStatus.FAILED.name(), null, false);
        }

        log.info("===> Creating new DiscoveryIssuerServiceImpl object");
        DiscoveryIssuerService discoveryIssuerService = new DiscoveryIssuerServiceImpl();
        ResponseEntity<String> responseEntityAuth = null;
        log.info("===> About to get authorization response");
        try {
            responseEntityAuth = discoveryIssuerService.callDiscoveryIssuerService(clientId, mccmnc, null, null);
            log.info("===> Successfully got authorization response");
            log.info("======================= Completed Step 1 or 3 - Discovery Issuer:  Received OIDC Config");
        }  catch (Exception ex) {
            String returnMessage = String.format("Authorization Failed: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("===> Authorization response is {}", responseEntityAuth.getBody());

        if (responseEntityAuth.getBody() == null) {
            String parseAuthorizationUrlError = "Not able to parse authorization URL from Oidc config";
            log.error(parseAuthorizationUrlError);
            return constructAuthorizationOidcResponse(false, parseAuthorizationUrlError, AuthorizationStatus.FAILED.name(), null);
        }

        String tokenEndPoint = discoveryIssuerService.getOidcValueForKey(responseEntityAuth.getBody(), TOKEN_ENDPOINT);
        String userInfoEndpoint = discoveryIssuerService.getOidcValueForKey(responseEntityAuth.getBody(), USERINFO_ENDPOINT);

        String signedAssertion = "";
        String tokenResponse = "";

        try {
            signedAssertion = getSignedAssertion(clientId, tokenEndPoint, mccmnc, code, clientKeyPairs, keyPair);
        } catch (Exception ex) {
            String returnMessage = String.format("===> Get Authorization Token Failed: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }

        TokenRequestBody tokenRequestBody = createTokenRequestBody(clientId, mccmnc, signedAssertion, code);

        try {
            tokenResponse = getTokenV2(tokenRequestBody, tokenEndPoint);
            log.info("Just got token response from getTokenV2: {}", tokenResponse);
        } catch (OauthException ex) {
            String returnedMessage = String.format("Error getting tokenV2: OAuthException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        } catch (Exception ex) {
            String returnedMessage = String.format("Error getting tokenV2: Exception: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("Token response from getTokenV2: {}", tokenResponse);

        ObjectMapper mapper = new ObjectMapper(new JsonFactory());
        JsonNode jsonNode = null;
        try {
            jsonNode = mapper.readTree(tokenResponse);
        } catch (JsonMappingException ex) {
            String returnedMessage = String.format("Error JSON parsing tokenResponse: JsonMappingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        } catch (JsonProcessingException ex) {
            String returnedMessage = String.format("Error JSON parsing tokenResponse: JsonProcessingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }
        String accessToken = ((ObjectNode) jsonNode).get("access_token").asText();
        log.info("===> Parsed accessToken: {}", accessToken);

        org.json.JSONObject userInfoResponse = null;

        try {
            userInfoResponse = getUserInfo(userInfoEndpoint, accessToken);
        } catch (Exception ex) {
            String returnedMessage = String.format("Error with getUserInfo: Exception: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("userInfoResponse: {}", userInfoResponse);

        if (userInfoResponse == null) {
            String returnedMessage = "User Info is empty.  This is considered abnormal, therefore an error";
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }

        JsonNode userInfoJson = null;

        mapper = new ObjectMapper(new JsonFactory());
        try {
            userInfoJson = mapper.readTree(userInfoResponse.toString());
        } catch (JsonMappingException ex) {
            String returnedMessage = String.format("Error converting JSONObject to JsonNode: JsonMappingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        } catch (JsonProcessingException ex) {
            String returnedMessage = String.format("Error converting JSONObject to JsonNode: JsonProcessingException: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }

        authorizationResponse = constructAuthorizationOidcResponse(true, "Get User Info Was Successful", AuthorizationStatus.SUCCESSFUL.name(), userInfoJson);
        log.info("Leaving getAuthorizationToken");
        return authorizationResponse;
    }

    public AuthorizationOidcResponse getAuthorizationServerInitiated(String clientId, String sub, String clientKeyPairs, String keyPair) {
        log.info("===> Calling");
        log.info("===> sub: {}", sub );

        AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

        if (sub == null || sub.trim().length() == 0) {
            return constructAuthorizationOidcResponse(false, "Authorization Verification failed.  Sub is empty", AuthorizationStatus.FAILED.name(), null, false);
        }

        log.info("===> Creating new DiscoveryIssuerServiceImpl object");
        DiscoveryIssuerService discoveryIssuerService = new DiscoveryIssuerServiceImpl();
        ResponseEntity<String> responseEntityAuth = null;
        log.info("===> About to get discovery issuer response");
        try {
            responseEntityAuth = discoveryIssuerService.callDiscoveryIssuerService(clientId, null, sub, null);
            log.info("===> Successfully got discovery issuer response");
            log.info("======================= Completed Step 1 or 3 - Discovery Issuer:  Received OIDC Config");
        }  catch (Exception ex) {
            String returnMessage = String.format("Authorization Failed: Discovery Issuer: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("===> Discovery Issuer response is {}", responseEntityAuth.getBody());

        if (responseEntityAuth.getBody() == null) {
            String parseAuthorizationUrlError = "Not able to parse authorization URL from Oidc config";
            log.error(parseAuthorizationUrlError);
            return constructAuthorizationOidcResponse(false, parseAuthorizationUrlError, AuthorizationStatus.FAILED.name(), null);
        }

        OidcUrlInfo oidcUrlInfo = discoveryIssuerService.buildOidcUrlInfo(responseEntityAuth.getBody());
        if (oidcUrlInfo == null) {
            return constructAuthorizationOidcResponse(false, "Error parsing OIDC info from Oidc config", AuthorizationStatus.FAILED.name(), null);
        }
        log.info("Populated OidcUrlInfo with endpoints and more");

        String signedAssertion = "";
        String tokenResponse = "";

        try {
            signedAssertion = getSignedAssertionServerInitiated(clientId, sub, oidcUrlInfo.getIssuer(), oidcUrlInfo.getServerInitiatedAuthorizationEndpoint(), clientKeyPairs, keyPair);
        } catch (Exception ex) {
            String returnMessage = String.format("===> Get Authorization Token Failed: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("Got signed assertion");

        ServerInitiatedRequestBody serverInitiatedRequestBody = createServerInitiatedRequestBody(clientId, sub, oidcUrlInfo.getIssuer(), oidcUrlInfo.getServerInitiatedAuthorizationEndpoint(), oidcUrlInfo.getServerInitiatedCancelEndpoint(), signedAssertion);
        log.info("Created ServerInitiatedRequestBody");

        String returnedMessage = null;
        try {
            returnedMessage = callServerInitiatedRequest(serverInitiatedRequestBody);
        } catch (Exception ex) {
            String returnMessage = String.format("===> Exception doing server-initiated request: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null, true, true, true);
        }

        return constructAuthorizationOidcResponse(true, "Server-Initiated Request Was Successful", AuthorizationStatus.SUCCESSFUL.name(), null);
    }

    private String getSignedAssertion(String clientId, String tokenEndpoint, String mccmnc, String code, String clientKeyPairs, String keyPair) throws Exception {
        log.info("Entering getSignedAssertion: tokenEndpoint: {}", tokenEndpoint);

        AssertionBody assertionBody = new AssertionBody();

        assertionBody.setAud(tokenEndpoint);
        assertionBody.setIss(clientId);
        assertionBody.setSub(clientId);
        // Create a version 4 UUID
        assertionBody.setJti(UUID.randomUUID().toString());
        // Casting to int truncates fractional portion of long if it exists
        int iat = (int)(new Date().getTime() / 1000);
        assertionBody.setIat(iat);
        int exp = iat + 30 * 60;
        assertionBody.setExp(exp);

        ObjectMapper mapper = new ObjectMapper();

        JSONObject parseKeyPairs = null;
        try {
            parseKeyPairs = JSONObjectUtils.parse(clientKeyPairs);
        } catch (ParseException ex) {
            String returnedMessage = String.format("JSONProcessingException: Error converting AssertionBody to JSON string: %s", ex.getMessage());
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        Object signingKey = parseKeyPairs.get(clientId);
        log.info("===> signingKey: " + signingKey);

        // String jwtKeyId = clientId + ".1623943437897";
        String jwtKeyId = signingKey == null ? "" : signingKey.toString();

        JwtHeaderAssertion jwtHeaderAssertion = createJwtHeaderAssertion(jwtKeyId);

        String jwtHeaderAssertionJsonStrng = null;
        String assertionBodyJsonString = null;
        // Convert Java POJO JwtHeaderAssertion object to JSON string
        // Convert Java POJO AssertionBody object to JSON string
        try {
            jwtHeaderAssertionJsonStrng = mapper.writeValueAsString(jwtHeaderAssertion);
            assertionBodyJsonString = mapper.writeValueAsString(assertionBody);
        } catch (JsonProcessingException ex) {
            String returnedMessage = String.format("JSONProcessingException: Error converting AssertionBody to JSON string: %s", ex.getMessage());
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        log.info("JwtHeaderAssertion JSON string: {}", jwtHeaderAssertionJsonStrng);
        log.info("AssertionBody JSON string: {}", assertionBodyJsonString);

        String unsignedAssertion = createUnsignedJwt(jwtHeaderAssertionJsonStrng, assertionBodyJsonString);
        log.info("unsignedAssertion: {}", unsignedAssertion);

        String signedAssertion = "";

        try {
            signedAssertion = createSignedRSAToken(unsignedAssertion, clientId, clientKeyPairs, keyPair);
        } catch (ParseException ex) {
            String returnedMessage = String.format("ParseException: Error signing unsigned assertion: %s", ex.getMessage());
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }  catch (JOSEException ex) {
            String returnedMessage = String.format("JOSEException: Error signing unsigned assertion: %s", ex.getMessage());
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        log.info("Leaving getSignedAssertion");

        return signedAssertion;
    }

    private String getSignedAssertionServerInitiated(String clientId, String sub, String issuer, String carrierAuthEndpoint, String clientKeyPairs, String keyPair) throws Exception {
        log.info("Entering getSignedAssertionServerInitiated");

        AuthorizationVerificationBody authVerificationBody = createAuthorizationVerificationBody(clientId, sub, carrierAuthEndpoint);

        ObjectMapper mapper = new ObjectMapper();

        JSONObject parseKeyPairs = null;
        try {
            parseKeyPairs = JSONObjectUtils.parse(clientKeyPairs);
        } catch (ParseException ex) {
            String returnedMessage = String.format("ParseException: Error converting clientKeyPairs JSON string to JSONObject: %s", ex.getMessage());
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        Object signingKey = parseKeyPairs.get(clientId);
        log.info("===> signingKey: " + signingKey);

        // String jwtKeyId = clientId + ".1623943437897";
        String jwtKeyId = signingKey == null ? "" : signingKey.toString();

        JwtHeaderAssertion jwtHeaderAssertion = createJwtHeaderAssertion(jwtKeyId);

        String jwtHeaderAssertionJsonStrng = null;
        String assertionBodyJsonString = null;
        // Convert Java POJO JwtHeaderAssertion object to JSON string
        // Convert Java POJO AssertionBody object to JSON string
        try {
            jwtHeaderAssertionJsonStrng = mapper.writeValueAsString(jwtHeaderAssertion);
            assertionBodyJsonString = mapper.writeValueAsString(authVerificationBody);
        } catch (JsonProcessingException ex) {
            String returnedMessage = String.format("JSONProcessingException: Error converting AssertionBody to JSON string: %s", ex.getMessage());
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        log.info("JwtHeaderAssertion JSON string: {}", jwtHeaderAssertionJsonStrng);
        log.info("AssertionBody JSON string: {}", assertionBodyJsonString);

        String unsignedAssertion = createUnsignedJwt(jwtHeaderAssertionJsonStrng, assertionBodyJsonString);
        log.info("unsignedAssertion: {}", unsignedAssertion);

        String signedAssertion = "";

        try {
            signedAssertion = createSignedRSAToken(unsignedAssertion, clientId, clientKeyPairs, keyPair);
        } catch (ParseException ex) {
            String returnedMessage = String.format("ParseException: Error signing unsigned assertion: %s", ex.getMessage());
            log.error("ParseException: Error creating signed assertion: {}", ex.getMessage());
            throw new Exception(returnedMessage);
        }  catch (JOSEException ex) {
            String returnedMessage = String.format("JOSEException: Error signing unsigned assertion: %s", ex.getMessage());
            log.error("ParseException: Error creating signed assertion: {}", ex.getMessage());
            throw new Exception(returnedMessage);
        }
        log.info("Leaving getSignedAssertion");

        return signedAssertion;
    }

    private TokenRequestBody createTokenRequestBody(String clientId, String mccmnc, String signedAssertion, String code) {
        log.info("Entering createTokenRequestBody");

        TokenRequestBody tokenRequestBody = new TokenRequestBody();

        tokenRequestBody.setGrantType("authorization_code");
        tokenRequestBody.setClientId(clientId);
        tokenRequestBody.setRedirectUri("http://localhost:4200");
        tokenRequestBody.setMccmnc(mccmnc);
        tokenRequestBody.setCode(code);
        tokenRequestBody.setClientAssertion(signedAssertion);
        tokenRequestBody.setClientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

        return tokenRequestBody;
    }

    private String createUnsignedJwt(String tokenHead, String tokenBody) {
        log.info("Entering createUnsignedJwt");
        String headString = encodeTokenString(tokenHead);
        String bodyString = encodeTokenString(tokenBody);
        StringBuilder sb = new StringBuilder();
        sb.append(headString).append(".").append(bodyString);
        return sb.toString();
    }

    /**
     * First, Base64 encode string, followed by replaced one or two equal signs at end of line with nothing (remove),
     * followed by encoding as a URI just like Javascript does where the '+' signs (spaces) become '%20'.
     * Also, replace all occurrences of "%xx" representing any of [~'()!] back to their literal counter-parts.
     * @param tokenPortion
     * @return
     */
    private String encodeTokenString(String tokenPortion) {
        log.info("Entering encodeTokenString");
        String base64EncodedTokenString = Base64.getEncoder().encodeToString(tokenPortion.getBytes());
        String replacedEncodedTokenString = base64EncodedTokenString.replaceAll("={1,2}$", "");
        return encodeURILikeJavascript(replacedEncodedTokenString);
    }

    private JwtHeaderAssertion createJwtHeaderAssertion(String jwtKeyId) {
        log.info("Entering createJwtHeaderAssertion");
        JwtHeaderAssertion jwtHeaderAssertion = new JwtHeaderAssertion();
        jwtHeaderAssertion.setAlg("RS256");
        jwtHeaderAssertion.setTyp("jwt");
        jwtHeaderAssertion.setKid(jwtKeyId);

        return jwtHeaderAssertion;
    }

    /**
     * Goes beyond the Java URL encoding, and further encodes according to Javascript encoding standards.
     * This attempts to be the equivalent of the Javascript encodeURI() method.
     * @param s This is the URI string to be encoded
     * @return
     */
    private String encodeURILikeJavascript(String s) {
        log.info("Entering encodeURILikeJavascript");
        String result = null;

        try {
            result = URLEncoder.encode(s, "UTF-8")
                    .replaceAll("\\+", "%20")
                    .replaceAll("\\%21", "!")
                    .replaceAll("\\%27", "'")
                    .replaceAll("\\%28", "(")
                    .replaceAll("\\%29", ")")
                    .replaceAll("\\%7E", "~");
        } catch (UnsupportedEncodingException e) {
            result = s;
        }

        return result;
    }

    /**
     * Takes the unsigned client assertion and signs it returning a signed assertion.  This relies heavily
     * on the nimbusds dependency, which is a popular Java and Android library for JSON Web Tokens (JWT).
     * @param jwtToken
     * @param clientId
     * @return
     * @throws ParseException
     * @throws JOSEException
     */
    private String createSignedRSAToken(String jwtToken, String clientId, String clientKeyPairs, String keyPair) throws ParseException, JOSEException {
        log.info("Entering createSignedRSAToken");
        log.info("clientKeyPairs: {}", clientKeyPairs);

        Object signingKey;

        // To not affect current functionality, if no clientId parameter is passed,
        // sign with the default playground's "testing_key"
        JSONObject parseKeyPairs = JSONObjectUtils.parse(clientKeyPairs);
        log.info("Parsed clientKeyPairs");

        if (clientId.equals("none")) {
            signingKey = parseKeyPairs.get("default");
        } else {
            signingKey = parseKeyPairs.get(clientId);
            if (signingKey == null) {
                throw new OauthException("Client ID to private key mapping not found", HttpStatus.BAD_REQUEST);
            }
        }
        log.info("signingKey: {}", signingKey);

        String[] splitString = jwtToken.split("\\.");

        log.info("Size of splitString: {}", splitString.length);

        log.info("~~~~~~~~~ JWT Header ~~~~~~~");
        String base64EncodedHeader = splitString[0];
        JWSHeader head = JWSHeader.parse(new Base64URL(base64EncodedHeader));


        log.info("~~~~~~~~~ JWT Body ~~~~~~~");
        String base64EncodedBody = splitString[1];
        Payload payload = new Payload(new Base64URL(base64EncodedBody));

        // RSA signatures require a public and private RSA key pair,
        // the public key must be made known to the JWS recipient to
        // allow the signatures to be verified

        log.info("keyPair: {}", keyPair);

        net.minidev.json.JSONObject parsedRsa = JSONObjectUtils.parse(keyPair);

        Object getSigningKey = parsedRsa.get(signingKey);
        String signingKeyToString = String.valueOf(getSigningKey);

        RSAKey rsaJWK = RSAKey.parse(signingKeyToString);
        RSAPrivateKey prK = (RSAPrivateKey) rsaJWK.toPrivateKey();
        RSAPublicKey puK = (RSAPublicKey) rsaJWK.toPublicKey();

        byte[] privateKeyEnc = prK.getEncoded();
        byte[] privateKeyPem = java.util.Base64.getEncoder().encode(privateKeyEnc);
        String privateKeyPemStr = new String(privateKeyPem);

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        // Prepare JWS object with simple string as payload
        JWSObject jwsObject = new JWSObject(head, payload);

        // Compute the RSA signature
        jwsObject.sign(signer);

        // To serialize to compact form, produces something like
        String s = jwsObject.serialize();
        log.info("Signed RSA Token:");
        log.info(s);

        // To parse the JWS and verify it, e.g. on client-side
        jwsObject = JWSObject.parse(s);

        JWSVerifier verifier = new RSASSAVerifier(puK);

        log.info("Verify: {}", jwsObject.verify(verifier));

        log.info("In RSA we trust! --> {}", jwsObject.getPayload().toString());
        return s;
    }

    /**
     * Makes REST POST call to carrier's token endpoint
     * @param tokenRequestBody This contains all neccessary parameters for obtaining auth token
     * @return
     */
    private String getTokenV2(TokenRequestBody tokenRequestBody, String tokenEndPoint) throws Exception {
        log.info("Entering getTokenV2");
        String message = null;
        HttpStatus status = null;
        try {

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add(GRANT_TYPE, tokenRequestBody.getGrantType());
            map.add(CODE, tokenRequestBody.getCode());
            map.add(CLIENT_ID, tokenRequestBody.getClientId());
            map.add(REDIRECT_URI, tokenRequestBody.getRedirectUri());
            map.add(CLIENT_ASSERTION_TYPE, tokenRequestBody.getClientAssertionType());
            map.add(CLIENT_ASSERTION, tokenRequestBody.getClientAssertion());
            log.info("Just created token request map");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            Object loggedHeader = headers.remove(HttpHeaders.AUTHORIZATION);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
            log.info("User Token v2>>Carrier endpoint: {}", tokenEndPoint);
            log.info("User Token v2>>Carrier Request: {}", loggedHeader);
            log.info("User Token v2>>Carrier Body: {}", map);
            log.info("User Token v2>>Request: {}", request);
            log.info("tokenEndPoint: {}", tokenEndPoint);

            ResponseEntity<String> response = restTemplate.exchange(tokenEndPoint, HttpMethod.POST, request,
                    String.class);
            log.info("Just made carrier token endpoint REST call");
            if (!response.getStatusCode().equals(HttpStatus.OK)) {
                throw new OauthException("Carrier thrown Exception: " + response.getStatusCodeValue());
            }
            message = response.getBody();
            log.info("User Token2 Response: {}", message);
        } catch (RestClientResponseException ex) {
            String returnedMessage = "";
            if (ex.getRawStatusCode() == 401) {
                returnedMessage = String.format("Error getTokenV2: HTTP 401: Unauthorized token: %s", ex.getMessage());
                log.error(returnedMessage);
                throw new Exception(returnedMessage);
            }
            if (ex.getResponseBodyAsByteArray().length > 0)
                returnedMessage = new String(ex.getResponseBodyAsByteArray());
            else
                returnedMessage = ex.getMessage();
            status = HttpStatus.BAD_REQUEST;
            log.error("HTTP 400: " + returnedMessage);
            throw new OauthException(returnedMessage, status);
        } catch (Exception ex) {
            String returnedMessage = String.format("Error getTokenV2: Error in calling Token end point: %s", ex.getMessage());
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        log.info("Leaving getTokenV2");
        return message;
    }

    /**
     * Use authorization token to get user info based on previously selected scopes.  It makes REST POST
     * call to carrier's userinfo endpoint.
     * @param url This is the userinfo endpoint URL
     * @param token  This is the authorization token
     * @return
     * @throws Exception
     */
    private org.json.JSONObject getUserInfo(String url, String token) throws Exception {
        log.info("Entering getUserInfo");
        RestTemplate restTemplateWithInterceptors = new RestTemplate();
        HttpStatus status = null;
        org.json.JSONObject body = null;
        String message = null;

        if(!token.substring(0, 7).equals("Bearer ")) {
            token = "Bearer " + token;
        }
        log.info("Just added Bearer as token prefix");

        try {
            List<ClientHttpRequestInterceptor> interceptors = restTemplateWithInterceptors.getInterceptors();
            if (CollectionUtils.isEmpty(interceptors)) {
                interceptors = new ArrayList<>();
            }

            interceptors.add(new XCIJVUserInfoHeaderInjectorInterceptor(token));
            restTemplateWithInterceptors.setInterceptors(interceptors);
            log.info("Just set interceptor to list");
            HttpHeaders headers = new HttpHeaders();
            HttpEntity<?> entityUserInfo = new HttpEntity<>(headers);
            log.info("HttpEntity<?> entityUserInfo: {}", entityUserInfo);
            log.info("getUserInfo: url: {}", url);
            HttpEntity<String> response = restTemplateWithInterceptors.exchange(url, HttpMethod.GET, entityUserInfo, String.class);
            log.info("Just did carrier userinfo REST call using userinfo_endpoint");
            body = new org.json.JSONObject(response.getBody());

        } catch (RestClientResponseException e) {

            if (e.getRawStatusCode() == 401) {
                status = HttpStatus.UNAUTHORIZED;
                message = "Unauthorized token";
                log.error("HTTP 401: " + message);
                throw new OauthException(message, status);
            }

            if (e.getResponseBodyAsByteArray().length > 0) {
                message = new String(e.getResponseBodyAsByteArray());
            } else {
                message = e.getMessage();
            }
            status = HttpStatus.BAD_REQUEST;
            log.error("HTTP 400: " + message);
            throw new OauthException(message, status);

        } catch (Exception e) {
            message = "Error in calling Bank app end point" + e.getMessage();
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            log.error("HTTP 500: " + message);
            throw new OauthException(message, status);
        }
        log.info("Leaving getUserInfo");

        return body;
    }

    private AuthorizationVerificationBody createAuthorizationVerificationBody(String clientId, String sub, String carrierAuthEndpoint) {

        AuthorizationVerificationBody authVerificationBody = new AuthorizationVerificationBody();

        authVerificationBody.setBaseUrl(carrierAuthEndpoint);
        authVerificationBody.setNotificationUri("/si_callback");
        authVerificationBody.setClientId(clientId);
        authVerificationBody.setSub(clientId);
        authVerificationBody.setIss(clientId);
        authVerificationBody.setIat((int)(new Date().getTime()));
        authVerificationBody.setExp((int)(new Date().getTime() + 300));
        authVerificationBody.setExpiresIn(1500);
        authVerificationBody.setResponseType("async_token");
        authVerificationBody.setHeaderType("application_json");

        authVerificationBody.setLoginHint(sub);
        authVerificationBody.setScope("openid");
        authVerificationBody.setAcrValues("a3");

        return authVerificationBody;
    }

    private ServerInitiatedRequestBody createServerInitiatedRequestBody(String clientId, String sub, String issuer, String serverInitiatedAuthEndpoint, String serverInitiatedCancelEndpoint, String signedAssertion) {

        ServerInitiatedRequestBody serverInitiatedRequestBody = new ServerInitiatedRequestBody();

        serverInitiatedRequestBody.setBaseUrl(serverInitiatedAuthEndpoint);
        serverInitiatedRequestBody.setNotificationUri("/si_callback");
        serverInitiatedRequestBody.setClientId(clientId);
        serverInitiatedRequestBody.setAud(issuer);
        serverInitiatedRequestBody.setSub(clientId);
        serverInitiatedRequestBody.setIss(clientId);
        serverInitiatedRequestBody.setIat((int)(new Date().getTime()));
        serverInitiatedRequestBody.setExp((int)(new Date().getTime() + 300));
        serverInitiatedRequestBody.setExpiresIn(1500);
        serverInitiatedRequestBody.setResponseType("async_token");
        serverInitiatedRequestBody.setHeaderType(HeaderTypeEnum.APPLICATION_JSON);

        serverInitiatedRequestBody.setLoginHint(sub);
        serverInitiatedRequestBody.setScope("openid");
        serverInitiatedRequestBody.setAcrValues("a3");

        serverInitiatedRequestBody.setCarrierAuthEndpoint(serverInitiatedAuthEndpoint);
        serverInitiatedRequestBody.setCarrierServerInitiatedCancelEndpoint(serverInitiatedCancelEndpoint);
        serverInitiatedRequestBody.setRequest(signedAssertion);

        return serverInitiatedRequestBody;
    }

    public void addToRequestIfPresent(HeaderTypeEnum headerType, String fieldName, String getFieldData, org.json.JSONObject requestBody, MultiValueMap<String, String> map) {
        if(headerType.equals(HeaderTypeEnum.X_WWW_FORM_URLENCODED)) {
            if(getFieldData != null && !getFieldData.trim().isEmpty()) {
                map.add(fieldName, getFieldData);
            }
        } else {
            if(getFieldData != null) {
                requestBody.put(fieldName, getFieldData);
            }
        }
    }

    public HttpEntity<String> buildJSONRequest(ServerInitiatedRequestBody serverInitiatedRequestBody){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);

        org.json.JSONObject requestBody = new org.json.JSONObject()
                .put(RESPONSE_TYPE, serverInitiatedRequestBody.getResponseType())
                .put(REDIRECT_URI, serverInitiatedRequestBody.getRedirectUri())
                .put(NOTIFICATION_URI, serverInitiatedRequestBody.getNotificationUri())
                .put(IAT, serverInitiatedRequestBody.getIat())
                .put(SUB, serverInitiatedRequestBody.getSub())
                .put(EXP, serverInitiatedRequestBody.getExp())
                .put(ISS, serverInitiatedRequestBody.getIss())
                .put(AUD, serverInitiatedRequestBody.getAud())
                .put(EXPIRES_IN, serverInitiatedRequestBody.getExpiresIn())
                .put(SCOPE, serverInitiatedRequestBody.getScope())
                .put(CORRELATION_ID, serverInitiatedRequestBody.getCorrelationId())
                .put(CLIENT_ID, serverInitiatedRequestBody.getClientId())
                .put(ACR_VALUES, serverInitiatedRequestBody.getAcrValues())
                .put(REQUEST, serverInitiatedRequestBody.getRequest());
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), CLIENT_NOTIFICATION_TOKEN, serverInitiatedRequestBody.getClientNotificationToken(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), LOGIN_HINT, serverInitiatedRequestBody.getLoginHint(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), LOGIN_HINT_TOKEN, serverInitiatedRequestBody.getLoginHintToken(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), STATE, serverInitiatedRequestBody.getState(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), CONTEXT, serverInitiatedRequestBody.getContext(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), NONCE, serverInitiatedRequestBody.getNonce(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), JTI, serverInitiatedRequestBody.getJti(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), SDK_VERSION, serverInitiatedRequestBody.getSdkVersion(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), OPTIONS, serverInitiatedRequestBody.getOptions(), requestBody, null);
        addToRequestIfPresent(serverInitiatedRequestBody.getHeaderType(), REFERRED_BINDING, serverInitiatedRequestBody.getReferredBinding(), requestBody, null);
        log.info("Authorize>>Carrier headers: {}", headers);

        HttpEntity<String> request = new HttpEntity(requestBody.toString(), headers);
        log.info("requestBody.toString(): {}", requestBody.toString());
        log.info("HttpEntity<String> request: {}", request);

        return request;
    }

    private String callServerInitiatedRequest(ServerInitiatedRequestBody serverInitiatedRequestBody) throws Exception {

        log.info("Entering callServerInitiatedRequest");
        HttpEntity request = null;
        String returnedMessage = null;

        if(serverInitiatedRequestBody.getHeaderType().equals(HeaderTypeEnum.X_WWW_FORM_URLENCODED)) {
            // request = buildURLEncodedRequest(serverInitiatedFlowRequestBody);
        } else {
            request = buildJSONRequest(serverInitiatedRequestBody);
        }
        log.info("Just created HTTPEntity with body for call to carrier's server initiated request");

        try {
            ResponseEntity<String> response = restTemplate.exchange(serverInitiatedRequestBody.getCarrierAuthEndpoint(), HttpMethod.POST, request,
                    String.class);

            log.info("Authorize>>Carrier endpoint: {}", serverInitiatedRequestBody.getCarrierAuthEndpoint());
            log.info("Authorize>>Carrier Body: {}", request);
            log.info("Carrier Response {}", response);
            returnedMessage = response.getBody();
            log.info("Server Initiated Response Body: {}", returnedMessage);
        } catch (RestClientResponseException ex) {
            if (ex.getResponseBodyAsByteArray().length > 0) {
                returnedMessage = new String(ex.getResponseBodyAsByteArray());
                log.error("Carrier Response Message Byte Array: {}", returnedMessage);
                throw new Exception(returnedMessage);
            } else {
                log.error("Carrier Response Error Message: {}", ex.getMessage());
                returnedMessage = ex.getMessage();
                throw new Exception(returnedMessage);
            }
        } catch (Exception e) {
            returnedMessage = "Error in calling Token end point" + e.getMessage();
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        log.info("Leaving callServerInitiatedRequest");

        return returnedMessage;
    }

    private String buildOptimizedDiscoveryRedirectUrl(List<String> scopes, String redirectUrl,  String clientId) throws Exception {
        UriComponents urlComponent = null;
        try {
            urlComponent = UriComponentsBuilder.newInstance()
                    .fromHttpUrl(OPTIMIZED_DISCOVERY_URL)
                    .queryParam("redirect_uri", redirectUrl)
                    .queryParam("client_id", clientId)
                    .queryParam("state", MNO_STATE_VALUE)
                    .queryParam("scope", URLEncoder.encode(convertListToSpaceDelimitedString(scopes), "UTF-8"))
                    .build().encode();
            log.info("===> Encoded Optimized Discovery Redirect URL: {}", urlComponent.toString());
        } catch (Exception ex) {
            String message = String.format("Error building encoded optimized discovery redirect URL: %s", ex.getMessage());
            log.error(message, ex);
            throw new Exception(message);
        }

        return urlComponent.toString();
    }

    private String convertListToSpaceDelimitedString(List<String> list) {

        String joinedString = String.join(" ", list);
        log.info("joinedString: {}", joinedString);
        return joinedString;
    }

    private JsonNode buildJsonNodeForOptimizedDiscoveryRedirectUrl(String optimizedRedirectUrl) {

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
