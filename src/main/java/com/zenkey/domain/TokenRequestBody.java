package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TokenRequestBody {

    public TokenRequestBody(String grantType, String clientId, String redirectUri, String mccmnc, String code, String clientAssertion, String clientAssertionType) {
        this.grantType = grantType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.mccmnc = mccmnc;
        this.code = code;
        this.clientAssertion = clientAssertion;
        this.clientAssertionType = clientAssertionType;
    }

    @JsonProperty("grant_type")
    private String grantType;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    @JsonProperty("mccmnc")
    private String mccmnc;

    @JsonProperty("code")
    private String code;

    @JsonProperty("client_assertion")
    private String clientAssertion;

    @JsonProperty("client_assertion_type")
    private String clientAssertionType;

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getMccmnc() {
        return mccmnc;
    }

    public void setMccmnc(String mccmnc) {
        this.mccmnc = mccmnc;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getClientAssertion() {
        return clientAssertion;
    }

    public void setClientAssertion(String clientAssertion) {
        this.clientAssertion = clientAssertion;
    }

    public String getClientAssertionType() {
        return clientAssertionType;
    }

    public void setClientAssertionType(String clientAssertionType) {
        this.clientAssertionType = clientAssertionType;
    }
}
