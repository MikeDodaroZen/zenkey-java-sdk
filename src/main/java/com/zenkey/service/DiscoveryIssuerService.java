package com.zenkey.service;

import com.zenkey.domain.OidcUrlInfo;
import org.springframework.http.ResponseEntity;

public interface DiscoveryIssuerService {

    ResponseEntity callDiscoveryIssuerService(String clientId, String mccmnc, String sub, String phoneNumber);

    OidcUrlInfo buildOidcUrlInfo(String oidcConfig);

}
