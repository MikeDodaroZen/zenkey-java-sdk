package com.zenkey.domain;

public class OidcUrlInfo {

    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String userInfoEndpoint;
    private String serverInitiatedAuthorizationEndpoint;
    private String serverInitiatedCancelEndpoint;
    private String mccmnc;
    private String issuer;

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getUserInfoEndpoint() {
        return userInfoEndpoint;
    }

    public void setUserInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public String getServerInitiatedAuthorizationEndpoint() {
        return serverInitiatedAuthorizationEndpoint;
    }

    public void setServerInitiatedAuthorizationEndpoint(String serverInitiatedAuthorizationEndpoint) {
        this.serverInitiatedAuthorizationEndpoint = serverInitiatedAuthorizationEndpoint;
    }

    public String getServerInitiatedCancelEndpoint() {
        return serverInitiatedCancelEndpoint;
    }

    public void setServerInitiatedCancelEndpoint(String serverInitiatedCancelEndpoint) {
        this.serverInitiatedCancelEndpoint = serverInitiatedCancelEndpoint;
    }

    public String getMccmnc() {
        return mccmnc;
    }

    public void setMccmnc(String mccmnc) {
        this.mccmnc = mccmnc;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
