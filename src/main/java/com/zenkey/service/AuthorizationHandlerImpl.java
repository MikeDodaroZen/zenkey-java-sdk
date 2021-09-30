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
import java.util.concurrent.TimeUnit;

public class AuthorizationHandlerImpl extends AbstractAuthorizationHandlerImpl implements AuthorizationHandler {

    RestTemplate restTemplate = new RestTemplate();

    /**
     * Attempt or re-attempt discovery-issuer, which requires known carrier.  Ultimately, should return an authorization code based
     * on successful call to carriers authorization endpoint.  The carrier is usually determined during discovery ui, which is usually a
     * prerequisite of this method.
     * @param clientId
     * @param mccmnc
     * @param redirectUri
     * @param scopes
     * @return
     */
    public AuthorizationOidcResponse getAuthorization(String clientId, String mccmnc, String redirectUri, List scopes) {
        log.info("===> Calling getAuthorization");
        log.info("===> mccmnc: {}", mccmnc);

        AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

        Optional<String> optMccmnc = Optional.ofNullable(mccmnc);
        if (optMccmnc.isEmpty()) {
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

    public AuthorizationOidcResponse getAuthorizationToken(String clientId, String mccmnc, String code, String clientKeyPairs, String keyPair, String redirectUri) {
        log.info("Entering getAuthorizationToken");
        AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

        Optional<String> optMccmnc = Optional.ofNullable(mccmnc);
        if (optMccmnc.isEmpty()) {
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

        TokenRequestBody tokenRequestBody = createTokenRequestBody(clientId, mccmnc, signedAssertion, code, redirectUri);

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

        Optional<org.json.JSONObject> optUserInfoResponse;

        try {
            optUserInfoResponse = getUserInfo(userInfoEndpoint, accessToken);
        } catch (Exception ex) {
            String returnedMessage = String.format("Error with getUserInfo: Exception: %s", ex.getMessage());
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("userInfoResponse: {}", optUserInfoResponse.get());

        if (optUserInfoResponse.isEmpty()) {
            String returnedMessage = "User Info is empty.  This is considered abnormal, therefore an error";
            log.error(returnedMessage);
            return constructAuthorizationOidcResponse(false, returnedMessage, AuthorizationStatus.FAILED.name(), null);
        }

        JsonNode userInfoJson = null;

        mapper = new ObjectMapper(new JsonFactory());
        try {
            userInfoJson = mapper.readTree(optUserInfoResponse.get().toString());
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

    public AuthorizationOidcResponse getAuthorizationServerInitiated(String clientId, String sub, String clientKeyPairs, String keyPair, String notificationUri) {
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

        String redirectUri = "http://localhost:4200";
        String correlationId = UUID.randomUUID().toString();

        int iat = (int)(new Date().getTime() / 1000);
        int exp = (int)(new Date().getTime() / 1000) + 3000;

        log.info("iat: {}", iat);
        log.info("iat String valueOf: {}", String.valueOf(iat));
        log.info("exp: {}", exp);
        log.info("exp String valueOf: {}", String.valueOf(exp));

        try {
            signedAssertion = getSignedAssertionServerInitiated(clientId, sub, oidcUrlInfo.getIssuer(), oidcUrlInfo.getServerInitiatedAuthorizationEndpoint(), clientKeyPairs, keyPair, redirectUri, notificationUri, correlationId, iat, exp);
        } catch (Exception ex) {
            String returnMessage = String.format("===> Get Authorization Token Failed: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
        }
        log.info("Got signed assertion");

        ServerInitiatedFlowRequestBody serverInitiatedFlowRequestBody = createServerInitiatedRequestBody(clientId, sub, oidcUrlInfo.getIssuer(), oidcUrlInfo.getServerInitiatedAuthorizationEndpoint(), oidcUrlInfo.getServerInitiatedCancelEndpoint(), signedAssertion, redirectUri, notificationUri, correlationId, iat, exp);
        log.info("Created ServerInitiatedRequestBody");

        String returnedMessage = null;
        try {
            returnedMessage = callServerInitiatedRequest(serverInitiatedFlowRequestBody);
        } catch (Exception ex) {
            String returnMessage = String.format("===> Exception doing server-initiated request: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null, true, true, true);
        }

        log.info("===> This response from carrier SI authorize endpoint should be the auth_req_id ");

        String authReqId = getJsonValueForKey(returnedMessage, AUTH_REQ_ID);

        String polledResponseWithToken = null;

        try {
            polledResponseWithToken = pollForServerInitiatedToken(authReqId, serverInitiatedFlowRequestBody.getNotificationUri());
        } catch (Exception ex) {
            String returnMessage = String.format("===> Exception polling for access tokenh: %s", ex.getMessage());
            log.error(returnMessage);
            return constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null, true, true, true);
        }

        String accessToken = getJsonValueForKey(polledResponseWithToken, SI_ACCESS_TOKEN);

        Optional<org.json.JSONObject> optUserInfoObject;

        try {
            optUserInfoObject = getUserInfo(oidcUrlInfo.getUserInfoEndpoint(), accessToken);
        } catch (Exception ex) {
            String returnedUserInfoError = String.format("Error with getUserInfo: Exception: %s", ex.getMessage());
            log.error(returnedUserInfoError);
            return constructAuthorizationOidcResponse(false, returnedUserInfoError, AuthorizationStatus.FAILED.name(), null);
        }

        JsonNode userInfoResponse = null;
        try {
            userInfoResponse = convertJsonObjectToJsonNode(optUserInfoObject.get());
        }  catch (Exception ex) {
            log.error(ex.getMessage());
            return constructAuthorizationOidcResponse(false, ex.getMessage(), AuthorizationStatus.FAILED.name(), null);
        }

        return constructAuthorizationOidcResponse(true, "Server-Initiated Request Was Successful", AuthorizationStatus.SUCCESSFUL.name(), userInfoResponse);
    }

    /**
     * First, an unsigned assertion is created followed by the signing of the assertion using the NimbusDS (JOSE) dependency.  The assertion is
     * composed of two portions: a header and body.  The body is composed of the AssertionBody object.  The header is composed of the
     * JwtHeaderAssertion object.  The two portions are delimited by a dot (".").  Before the signing of the assertion, it is first BASE64
     * encoded, followed by regular javascript-like encoding.
     * @param clientId
     * @param tokenEndpoint
     * @param mccmnc
     * @param code
     * @param clientKeyPairs
     * @param keyPair
     * @return
     * @throws Exception
     */
    private String getSignedAssertion(String clientId, String tokenEndpoint, String mccmnc, String code, String clientKeyPairs, String keyPair) throws Exception {
        log.info("Entering getSignedAssertion: tokenEndpoint: {}", tokenEndpoint);

        // Casting to int truncates fractional portion of long if it exists
        int iat = (int)(new Date().getTime() / 1000);
        int exp = iat + 30 * 60;

        AssertionBody assertionBody = new AssertionBody(clientId, clientId, tokenEndpoint, UUID.randomUUID().toString(), iat, exp);

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

    private String getSignedAssertionServerInitiated(String clientId, String sub, String issuer, String carrierAuthEndpoint, String clientKeyPairs, String keyPair, String redirectUri, String notificationUri, String correlationId, int iat, int exp) throws Exception {
        log.info("Entering getSignedAssertionServerInitiated");

        AuthorizationVerificationBody authVerificationBody = createAuthorizationVerificationBody(clientId, sub, carrierAuthEndpoint, issuer, redirectUri, notificationUri, correlationId, iat, exp);

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

        /**
         * Play with JwsHeader
         */
        log.info("About to play with JWSHeader");
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwtKeyId).type(JOSEObjectType.JWT).build();
        log.info("JWSHeader toString: {}", jwsHeader.toString());
        log.info("JWSHeader JSON Object JSON String: {}", jwsHeader.toJSONObject().toJSONString());
        log.info("JWSHeader JSON Object String: {}", jwsHeader.toJSONObject().toString());

        //-------------------------------------------

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

    /**
     * Creates a TokenRequestBody that is used in the body of the request of the carrier's POST token endpoint.
     * @param clientId
     * @param mccmnc
     * @param signedAssertion
     * @param code
     * @return
     */
    private TokenRequestBody createTokenRequestBody(String clientId, String mccmnc, String signedAssertion, String code, String redirectUri) {
        log.info("Entering createTokenRequestBody");

        return new TokenRequestBody(AUTHORIZATION_CODE, clientId, redirectUri, mccmnc, code, signedAssertion, CLIENT_ASSERTION_TYPE_VALUE);

    }

    /**
     * Creates the assertion from the header and body portions, and does encoding, including Base64 and regular encoding.
     * @param tokenHead
     * @param tokenBody
     * @return
     */
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

    /**
     * Creates header portion of assertion
     * @param jwtKeyId
     * @return
     */
    private JwtHeaderAssertion createJwtHeaderAssertion(String jwtKeyId) {
        log.info("Entering createJwtHeaderAssertion");
        JwtHeaderAssertion jwtHeaderAssertion = new JwtHeaderAssertion(JWT_HEADER_ASSERTION_ALG, JWT_HEADER_ASSERTION_TYPE, jwtKeyId);

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
     * Takes the unsigned client assertion and signs it returning a provided signed assertion.  This relies heavily
     * on the nimbusds (JOSE) dependency, which is a popular Java and Android library for JSON Web Tokens (JWT).
     * @param jwtToken
     * @param clientId
     * @param clientKeyPairs
     * @param keyPair
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
    private Optional<org.json.JSONObject> getUserInfo(String url, String token) throws Exception {
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

        return Optional.ofNullable(body);
    }

    /**
     * Creates AuthorizationVerificationBody for server-initiated request
     * @param clientId
     * @param sub
     * @param carrierAuthEndpoint
     * @return
     */
    private AuthorizationVerificationBody createAuthorizationVerificationBody(String clientId, String sub, String carrierAuthEndpoint, String issuer, String redirectUri, String notificationUri, String correlationId, int iat, int exp) {

        return new AuthorizationVerificationBody(carrierAuthEndpoint, notificationUri, sub, iat, exp, clientId, clientId, EXPIRES_IN_VALUE, SCOPE_OPENID, ASYNC_TOKEN, redirectUri, correlationId, clientId, ACR_VALUES_A3, sub);
    }

    /**
     * Creates ServerInitiatedFlowRequestBody POJO that is used for constructing the server-initiated request body.
     * @param clientId
     * @param sub
     * @param issuer
     * @param serverInitiatedAuthEndpoint
     * @param serverInitiatedCancelEndpoint
     * @param signedAssertion
     * @param redirectUri
     * @param correlationId
     * @param iat
     * @param exp
     * @return
     */
    private ServerInitiatedFlowRequestBody createServerInitiatedRequestBody(String clientId, String sub, String issuer, String serverInitiatedAuthEndpoint, String serverInitiatedCancelEndpoint, String signedAssertion, String redirectUri, String notificationUri, String correlationId, int iat, int exp) {

        return new ServerInitiatedFlowRequestBody(SCOPE_OPENID,
                serverInitiatedAuthEndpoint,
                ServerInitiatedFlowRequestBody.ResponseTypeEnum.ASYNC_TOKEN,
                ServerInitiatedFlowRequestBody.HeaderTypeEnum.APPLICATION_JSON,
                serverInitiatedAuthEndpoint,
                redirectUri,
                notificationUri,
                String.valueOf(iat),
                clientId,
                String.valueOf(exp),
                clientId,
                issuer,
                clientId,
                String.valueOf(EXPIRES_IN_VALUE),
                correlationId,
                ACR_VALUES_A3,
                sub,
                signedAssertion);

        // serverInitiatedFlowRequestBody.setCarrierServerInitiatedCancelEndpoint(serverInitiatedCancelEndpoint);

    }

    public void addToRequestIfPresent(ServerInitiatedFlowRequestBody.HeaderTypeEnum headerType, String fieldName, String getFieldData, org.json.JSONObject requestBody, MultiValueMap<String, String> map) {
        if(headerType.equals(ServerInitiatedFlowRequestBody.HeaderTypeEnum.X_WWW_FORM_URLENCODED)) {
            if(getFieldData != null && !getFieldData.trim().isEmpty()) {
                map.add(fieldName, getFieldData);
            }
        } else {
            if(getFieldData != null) {
                requestBody.put(fieldName, getFieldData);
            }
        }
    }

    /**
     * Build request body for server-initiated request that is made to carrier.  The body includes the encrypted client assertion.
     * @param serverInitiatedFlowRequestBody
     * @return
     */
    public HttpEntity<String> buildJSONRequest(ServerInitiatedFlowRequestBody serverInitiatedFlowRequestBody){
        log.info("String representation of response_type: {}", serverInitiatedFlowRequestBody.getResponseType().name());
        log.info("String representation of response_type: {}", serverInitiatedFlowRequestBody.getResponseType().toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);

        org.json.JSONObject requestBody = new org.json.JSONObject()
                .put(BASE_URL, serverInitiatedFlowRequestBody.getBaseUrl())
                .put(RESPONSE_TYPE, serverInitiatedFlowRequestBody.getResponseType().toString())
                // .put(RESPONSE_TYPE, serverInitiatedFlowRequestBody.getResponseType().name())
                .put(REDIRECT_URI, serverInitiatedFlowRequestBody.getRedirectUri())
                .put(NOTIFICATION_URI, serverInitiatedFlowRequestBody.getNotificationUri())
                .put(IAT, Long.valueOf(serverInitiatedFlowRequestBody.getIat()))
                .put(SUB, serverInitiatedFlowRequestBody.getSub())
                .put(EXP, Long.valueOf(serverInitiatedFlowRequestBody.getExp()))
                .put(ISS, serverInitiatedFlowRequestBody.getIss())
                .put(AUD, serverInitiatedFlowRequestBody.getAud())
                .put(EXPIRES_IN, Integer.valueOf(serverInitiatedFlowRequestBody.getExpiresIn()))
                .put(SCOPE, serverInitiatedFlowRequestBody.getScope())
                .put(CORRELATION_ID, serverInitiatedFlowRequestBody.getCorrelationId())
                .put(CLIENT_ID, serverInitiatedFlowRequestBody.getClientId())
                .put(ACR_VALUES, serverInitiatedFlowRequestBody.getAcrValues())
                .put(CARRIER_AUTH_ENDPOINT, serverInitiatedFlowRequestBody.getCarrierAuthEndpoint())
                .put(HEADER_TYPE, serverInitiatedFlowRequestBody.getHeaderType().toString())
                .put(REQUEST, serverInitiatedFlowRequestBody.getRequest());
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), CLIENT_NOTIFICATION_TOKEN, serverInitiatedFlowRequestBody.getClientNotificationToken(), requestBody, null);
        addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), LOGIN_HINT, serverInitiatedFlowRequestBody.getLoginHint(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), LOGIN_HINT_TOKEN, serverInitiatedFlowRequestBody.getLoginHintToken(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), STATE, serverInitiatedFlowRequestBody.getState(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), CONTEXT, serverInitiatedFlowRequestBody.getContext(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), NONCE, serverInitiatedFlowRequestBody.getNonce(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), JTI, serverInitiatedFlowRequestBody.getJti(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), SDK_VERSION, serverInitiatedFlowRequestBody.getSdkVersion(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), OPTIONS, serverInitiatedFlowRequestBody.getOptions(), requestBody, null);
        // addToRequestIfPresent(serverInitiatedFlowRequestBody.getHeaderType(), REFERRED_BINDING, serverInitiatedFlowRequestBody.getReferredBinding(), requestBody, null);
        log.info("Authorize>>Carrier headers: {}", headers);

        HttpEntity<String> request = new HttpEntity(requestBody.toString(), headers);
        log.info("requestBody.toString(): {}", requestBody.toString());
        log.info("HttpEntity<String> request: {}", request);

        return request;
    }

    /**
     * Call the carrier's server-initiated authorize endpoint returning the auth_req_id along with the correlation_id and expires_in
     * @param serverInitiatedFlowRequestBody
     * @return
     * @throws Exception
     */
    private String callServerInitiatedRequest(ServerInitiatedFlowRequestBody serverInitiatedFlowRequestBody) throws Exception {

        log.info("Entering callServerInitiatedRequest");
        HttpEntity request = null;
        String returnedMessage = null;

        if(serverInitiatedFlowRequestBody.getHeaderType().equals(HeaderTypeEnum.X_WWW_FORM_URLENCODED)) {
            // request = buildURLEncodedRequest(serverInitiatedFlowRequestBody);
        } else {
            request = buildJSONRequest(serverInitiatedFlowRequestBody);
        }
        log.info("Just created HTTPEntity with body for call to carrier's server initiated request");

        try {
            ResponseEntity<String> response = restTemplate.exchange(serverInitiatedFlowRequestBody.getCarrierAuthEndpoint(), HttpMethod.POST, request,
                    String.class);

            log.info("Authorize>>Carrier endpoint: {}", serverInitiatedFlowRequestBody.getCarrierAuthEndpoint());
            log.info("Authorize>>Carrier Body: {}", request);
            log.info("Carrier Response {}", response);
            returnedMessage = response.getBody();
            log.info("Server Initiated Response Body: {}", returnedMessage);
        } catch (RestClientResponseException ex) {
            if (ex.getResponseBodyAsByteArray().length > 0) {
                returnedMessage = new String(ex.getResponseBodyAsByteArray());
                log.error("Carrier Response Message Byte Array: code: {}  message: {}", ex.getRawStatusCode() , returnedMessage);
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

    /**
     * Using a TimerTask that both sets timer interval, and has implementation code executed every nth interval, call the SP
     * endpoint that checks if there is token returned from the carrier based on the user responding to push request.
     * The returned token response is stored in a map so that it can be checked in the caller method.
     * @param timer
     * @param interval
     * @param authReqId
     * @param notificationUrl
     * @param tokenMap
     */
    public void setInterval(Timer timer, int interval, String authReqId, String notificationUrl, final Map<String,String> tokenMap) {
        log.info("===> Entering setInterval");
        // String tokenResponse = null;
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                log.info("===> This executes every nth seconds based on interval");
                String tokenResponse = null;
                try {
                    tokenResponse = getServerInitiatedToken(authReqId, notificationUrl);
                } catch (Exception ex) {

                }
                if (tokenResponse != null) {
                    tokenMap.put(authReqId, tokenResponse);
                }
            }
        },0, interval);
        log.info("===> Leaving setInterval");
    }

    /**
     * Poll the carrier for an access token for the pending SI request represented by the provided auth_req_id based on the user
     * responding to the push request sent to their phone.  The token is not sent by the carrier until the user responds to the
     * push request.
     * @param authReqId
     * @param notificationUrl
     * @return
     * @throws Exception
     */
    private String pollForServerInitiatedToken(String authReqId, String notificationUrl) throws Exception {
        log.info("===> Entering pollForServerInitiatedToken");

        Map<String, String> tokenMap = new HashMap<>();

        Timer timer = new Timer();

        setInterval(timer, POLL_NOTIFICATION_TIME_INTERVAL, authReqId, notificationUrl, tokenMap);

        int totalTime = POLL_NOTIFICATION_TIME_PERIOD; // in milliseconds
        long startTime = System.currentTimeMillis();
        boolean toFinish = false;

        /*
        Stay in this loop until either timeout period (POLL_NOTIFICATION_TIME_PERIOD) is reached or until a valid token response
        is detected in the tokenMap.
         */
        while (!toFinish)
        {
            log.info("===> Still within timeout period");
            if (tokenMap.get(authReqId) != null) {
                log.info("===> Found authReqId in tokenMap");
                timer.cancel();
                return tokenMap.get(authReqId);
            }
            toFinish = (System.currentTimeMillis() - startTime >= totalTime);
        }
        timer.cancel();
        log.info("===> Exceeded timeout period.  Timer cancelled.");
        // This is only reached if no valid token response is detected in tokenMap before timeout period (POLL_NOTIFICATION_TIME_PERIOD)
        return null;
    }

    /**
     * Poll the carrier for an access token for the pending SI request represented by the provided auth_req_id based on the user
     * responding to the push request sent to their phone.  The token is not sent by the carrier until the user responds to the
     * push request.
     * @param authReqId
     * @param notificationUrl
     * @return
     * @throws Exception
     */
    private String getServerInitiatedToken(String authReqId, String notificationUrl) throws Exception {

        log.info("===> Entering getServerInitiatedToken");

        UriComponents urlComponent = null;
        try {
            urlComponent = UriComponentsBuilder.newInstance()
                    .fromHttpUrl(notificationUrl + '/' + authReqId)
                    .build().encode();
            log.info("===> si_callback URL: {}", urlComponent.toString());
        } catch (Exception ex) {
            String message = String.format("Error building si_callback URL that attempts to obtain access token: %s", ex.getMessage());
            log.error(message, ex);
            throw new Exception(message);
        }

        String returnedMessage = null;
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(urlComponent.toString(), String.class);

            log.info("si_callback/{auth_req_id} endpoint: {}", urlComponent.toString());
            log.info("si_callback Response {}", response);
            returnedMessage = response.getBody();
            log.info("si_callback Response Body: {}", returnedMessage);
        } catch (RestClientResponseException ex) {
            if (ex.getResponseBodyAsByteArray().length > 0) {
                returnedMessage = new String(ex.getResponseBodyAsByteArray());
                log.error("si_callback Response Message Byte Array: code: {}  message: {}", ex.getRawStatusCode() , returnedMessage);
                throw new Exception(returnedMessage);
            } else {
                log.error("si_callback Response Error Message: {}", ex.getMessage());
                returnedMessage = ex.getMessage();
                throw new Exception(returnedMessage);
            }
        } catch (Exception e) {
            returnedMessage = "Error in calling Token end point" + e.getMessage();
            log.error(returnedMessage);
            throw new Exception(returnedMessage);
        }
        log.info("===> Entering getServerInitiatedToken");
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

}
