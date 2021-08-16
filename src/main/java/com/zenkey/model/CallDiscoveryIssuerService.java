package com.zenkey.model;

import com.zenkey.service.DiscoveryIssuerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;


public class CallDiscoveryIssuerService {

    @Autowired
    DiscoveryIssuerService discoveryIssuerService;

    public ResponseEntity getDiscoveryIssuer(String clientId, String mccmnc, String sub, String phoneNumber){
        return  discoveryIssuerService.callDiscoveryIssuerService(clientId,mccmnc,sub,phoneNumber);
    }
}
