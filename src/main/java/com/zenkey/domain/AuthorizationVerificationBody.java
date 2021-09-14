package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthorizationVerificationBody {

    @JsonProperty("baseUrl")
    private String baseUrl;

    @JsonProperty("notification_uri")
    private String notificationUri;

    @JsonProperty("sub")
    private String sub;

    @JsonProperty("iat")
    private int iat;

    @JsonProperty("exp")
    private int exp;

    @JsonProperty("iss")
    private String iss;

    @JsonProperty("aud")
    private String aud;

    @JsonProperty("expires_in")
    private int expiresIn;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("response_type")
    private String responseType;

    @JsonProperty("header_type")
    private String headerType;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    @JsonProperty("correlation_id")
    private String correlation_id;

    // @JsonProperty("client_notification_token")
    // private String clientNotificationToken;

    // @JsonProperty("jti")
    // private String jti;

    // @JsonProperty("sdk_version")
    // private String sdkVersion;

    // @JsonProperty("prompt")
    // private String prompt;

    // @JsonProperty("options")
    // private String options;

    @JsonProperty("client_id")
    private String clientId;

    // @JsonProperty("state")
    // private String state;

    // @JsonProperty("nonce")
    // private String nonce;

    @JsonProperty("acr_values")
    private String acrValues;

    @JsonProperty("login_hint")
    private String loginHint;

    // @JsonProperty("login_hint_token")
    // private String loginHintToken;

    // @JsonProperty("context")
    // private String context;

    // @JsonProperty("referred_binding")
    // private String referredBinding;

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getNotificationUri() {
        return notificationUri;
    }

    public void setNotificationUri(String notificationUri) {
        this.notificationUri = notificationUri;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public int getIat() {
        return iat;
    }

    public void setIat(int iat) {
        this.iat = iat;
    }

    public int getExp() {
        return exp;
    }

    public void setExp(int exp) {
        this.exp = exp;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getHeaderType() {
        return headerType;
    }

    public void setHeaderType(String headerType) {
        this.headerType = headerType;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getCorrelation_id() {
        return correlation_id;
    }

    public void setCorrelation_id(String correlation_id) {
        this.correlation_id = correlation_id;
    }

    /*
    public String getClientNotificationToken() {
        return clientNotificationToken;
    }

    public void setClientNotificationToken(String clientNotificationToken) {
        this.clientNotificationToken = clientNotificationToken;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getSdkVersion() {
        return sdkVersion;
    }

    public void setSdkVersion(String sdkVersion) {
        this.sdkVersion = sdkVersion;
    }

    public String getPrompt() {
        return prompt;
    }

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    public String getOptions() {
        return options;
    }

    public void setOptions(String options) {
        this.options = options;
    }
     */

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }


    /*
    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }
     */

    public String getAcrValues() {
        return acrValues;
    }

    public void setAcrValues(String acrValues) {
        this.acrValues = acrValues;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public void setLoginHint(String loginHint) {
        this.loginHint = loginHint;
    }

    /*
    public String getLoginHintToken() {
        return loginHintToken;
    }

    public void setLoginHintToken(String loginHintToken) {
        this.loginHintToken = loginHintToken;
    }

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public String getReferredBinding() {
        return referredBinding;
    }

    public void setReferredBinding(String referredBinding) {
        this.referredBinding = referredBinding;
    }
     */
}
