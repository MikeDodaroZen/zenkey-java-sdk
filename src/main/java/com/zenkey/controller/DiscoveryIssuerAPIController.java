package com.zenkey.controller;


import com.zenkey.service.DiscoveryIssuerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api"})
public class DiscoveryIssuerAPIController {

    @Autowired
    DiscoveryIssuerService discoveryIssuerService;

    @GetMapping("/home")
    public String hello() {
        return "Server Initiated Request Service is running";
    }

    @GetMapping("/call-dis-issuer-api")
    public ResponseEntity callDiscoveryIssuerAPI(){
        String clientId = "ccid-oauthplayground1";
        String mccmnc = "310260";
        String sub = null;                // "310260-U-2e0934d5-8c7f-429e-88ac-338116dc05e9";
        String phoneNumber = "13478919548";
       ResponseEntity responseEntity = discoveryIssuerService.callDiscoveryIssuerService(clientId,mccmnc,sub,phoneNumber);
       return responseEntity;
    }
}
