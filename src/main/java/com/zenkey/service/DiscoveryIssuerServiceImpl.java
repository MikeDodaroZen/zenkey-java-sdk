package com.zenkey.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.zenkey.domain.OidcUrlInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class DiscoveryIssuerServiceImpl extends AbstractAuthorizationHandlerImpl implements DiscoveryIssuerService {

    private static final Logger log = LoggerFactory.getLogger(DiscoveryIssuerServiceImpl.class);

    private RestTemplate restTemplate = new RestTemplate();

    public ResponseEntity callDiscoveryIssuerService(String clientId, String mccmnc, String sub, String phoneNumber) {

        ResponseEntity<String> responseEntity = null;

        try {
            UriComponentsBuilder urlBuilder = UriComponentsBuilder.newInstance()
                    .fromHttpUrl(DISCOVERY_ISSUER_URL)
                    .queryParam("client_id", clientId);
            if (mccmnc != null) {
                urlBuilder = urlBuilder.queryParam("mccmnc", mccmnc);
            }
            if (sub != null) {
                urlBuilder = urlBuilder.queryParam("sub", sub);
            }
            if(phoneNumber != null){
                urlBuilder = urlBuilder.queryParam("phone_number", phoneNumber);
            }

            UriComponents urlComponent = urlBuilder.build().encode();
            log.info("===> DiscoveryIssuer URL: " + urlComponent.toString());
            responseEntity = restTemplate.getForEntity(urlComponent.toString(), String.class);

            log.info("===> ResponseEntity from DiscoveryIssuer: " + responseEntity);
            log.info("===> ResponseEntity Status from DiscoveryIssuer: " + responseEntity.getStatusCode());
            log.info("===> ResponseEntity Body from DiscoveryIssuer: " + responseEntity.getBody());

        } catch (Exception ex) {
            log.error("Error calling discovery issuer API " + ex.getMessage());

        }
        return responseEntity;
    }

    public JsonNode getOidcAsJson(String oidcConfig) {
        log.info("===> Entering getOidcAsJson");
        JsonNode jsonNode = null;
        ObjectMapper mapper = new ObjectMapper(new JsonFactory());

        try {
            jsonNode = mapper.readTree(oidcConfig);
            log.info("===> Just parsed oidcConfig object into JsonNode tree object");
        } catch (Exception ex) {
            log.info("===> Error parsing Oidc config");
            return null;
        }
        return jsonNode;
    }

    public OidcUrlInfo buildOidcUrlInfo(String oidcConfig) {
        log.info("===> Entering buildOidcUrlInfo");

        OidcUrlInfo oidcUrlInfo = new OidcUrlInfo();

        JsonNode jsonNode = null;
        ObjectMapper mapper = new ObjectMapper(new JsonFactory());

        try {
            jsonNode = mapper.readTree(oidcConfig);
            log.info("===> Just parsed oidcConfig object into JsonNode tree object");
        } catch (Exception ex) {
            log.info("===> Error parsing Oidc config");
            return null;
        }
        String authorizationUrl = ((ObjectNode) jsonNode).get("authorization_endpoint").asText();
        String tokenUrl = ((ObjectNode) jsonNode).get("token_endpoint").asText();
        String userInfoUrl = ((ObjectNode) jsonNode).get("userinfo_endpoint").asText();
        String serverInitiatedAuthUrl = ((ObjectNode) jsonNode).get("server_initiated_authorization_endpoint").asText();
        String serverInitiatedCancelUrl = ((ObjectNode) jsonNode).get("server_initiated_cancel_endpoint").asText();
        String mccmnc = ((ObjectNode) jsonNode).get("mccmnc").asText();
        String issuer = ((ObjectNode) jsonNode).get("issuer").asText();

        oidcUrlInfo.setAuthorizationEndpoint(authorizationUrl);
        oidcUrlInfo.setTokenEndpoint(tokenUrl);
        oidcUrlInfo.setUserInfoEndpoint(userInfoUrl);
        oidcUrlInfo.setServerInitiatedAuthorizationEndpoint(serverInitiatedAuthUrl);
        oidcUrlInfo.setServerInitiatedCancelEndpoint(serverInitiatedCancelUrl);
        oidcUrlInfo.setMccmnc(mccmnc);
        oidcUrlInfo.setIssuer(issuer);

        return oidcUrlInfo;
    }

    /**
     * Get value from carrier's OIDC JSON tree for provided key
     * @param oidcConfig
     * @param key
     * @return
     */
    public String getOidcValueForKey(String oidcConfig, String key) {
        log.info("===> Entering getOidcValueForKey");

        JsonNode jsonNode = null;
        ObjectMapper mapper = new ObjectMapper(new JsonFactory());

        try {
            jsonNode = mapper.readTree(oidcConfig);
            log.info("===> Just parsed oidcConfig object into JsonNode tree object");
        } catch (Exception ex) {
            log.info("===> Error parsing Oidc config");
            return null;
        }

        if (((ObjectNode) jsonNode).get(key) == null) {
            return null;
        }

        return ((ObjectNode) jsonNode).get(key).asText();
    }

}
