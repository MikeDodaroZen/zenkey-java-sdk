package com.zenkey.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Service
public class DiscoveryIssuerServiceImpl implements DiscoveryIssuerService {

    private RestTemplate restTemplate = new RestTemplate();

    public ResponseEntity callDiscoveryIssuerService(String clientId, String mccmnc, String sub, String phoneNumber) {

        ResponseEntity<Object> responseEntity = null;

        try {
            UriComponentsBuilder urlBuilder = UriComponentsBuilder.newInstance()
                    .fromHttpUrl("https://discoveryissuer-dev.myzenkey.com/.well-known/openid_configuration")
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
            responseEntity = restTemplate.getForEntity(urlComponent.toString(), Object.class);

            log.info("===> ResponseEntity from DiscoveryIssuer: " + responseEntity);
            log.info("===> ResponseEntity Status from DiscoveryIssuer: " + responseEntity.getStatusCode());
            log.info("===> ResponseEntity Body from DiscoveryIssuer: " + responseEntity.getBody());
        } catch (Exception ex) {
            log.error("Error calling discovery issuer API " + ex.getMessage());

        }
        return responseEntity;
    }

}
