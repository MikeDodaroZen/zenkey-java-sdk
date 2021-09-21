package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;

import java.math.BigDecimal;

@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaPKMSTServerCodegen", date = "2019-10-02T15:41:59.360Z")

public class ServerInitiatedFlowRequestBody {
  @JsonProperty("sdk_version")
  private String sdkVersion = null;

  @JsonProperty("scope")
  private String scope = null;

  /**
   * Gets or Sets prompt
   */
  public enum PromptEnum {
    NONE("none"),
    
    LOGIN("login"),
    
    CONSENT("consent");

    private String value;

    PromptEnum(String value) {
      this.value = value;
    }

    @Override
    @JsonValue
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static PromptEnum fromValue(String text) {
      for (PromptEnum b : PromptEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
  }

  @JsonProperty("prompt")
  private PromptEnum prompt = null;

  /**
   * Gets or Sets responseType
   */
  public enum ResponseTypeEnum {
    CODE("code"),
    
    ASYNC_TOKEN("async_token");

    private String value;

    ResponseTypeEnum(String value) {
      this.value = value;
    }

    @Override
    @JsonValue
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static ResponseTypeEnum fromValue(String text) {
      for (ResponseTypeEnum b : ResponseTypeEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
  }

  public enum HeaderTypeEnum {
    APPLICATION_JSON("application_json"),

    X_WWW_FORM_URLENCODED("x_www_form_urlencoded");

    private String value;

    HeaderTypeEnum(String value) {
      this.value = value;
    }

    @Override
    @JsonValue
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static HeaderTypeEnum fromValue(String text) {
      for (HeaderTypeEnum b : HeaderTypeEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
  }

  @JsonProperty("baseUrl")
  private String baseUrl = null;

  @JsonProperty("response_type")
  private ResponseTypeEnum responseType = null;

  @JsonProperty("header_type")
  private HeaderTypeEnum headerType = null;

  @JsonProperty("carrier_auth_endpoint")
  private String carrierAuthEndpoint = null;

  @JsonProperty("redirect_uri")
  private String redirectUri = null;

  @JsonProperty("notification_uri")
  private String notificationUri = null;

  @JsonProperty("iat")
  private String iat = null;

  @JsonProperty("sub")
  private String sub = null;

  @JsonProperty("exp")
  private String exp = null;

  @JsonProperty("iss")
  private String iss = null;

  @JsonProperty("aud")
  private String aud = null;

  @JsonProperty("client_id")
  private String clientId = null;

  @JsonProperty("expires_in")
  private String expiresIn = null;

  @JsonProperty("correlation_id")
  private String correlationId = null;

  @JsonProperty("acr_values")
  private String acrValues = null;

  @JsonProperty("client_notification_token")
  private String clientNotificationToken = null;

  @JsonProperty("login_hint_token")
  private String loginHintToken = null;

  @JsonProperty("login_hint")
  private String loginHint = null;

  @JsonProperty("id_token_hint")
  private String idTokenHint = null;

  @JsonProperty("state")
  private String state = null;

  @JsonProperty("context")
  private String context = null;

  @JsonProperty("nonce")
  private String nonce = null;

  @JsonProperty("jti")
  private String jti = null;

  @JsonProperty("options")
  private String options = null;

  @JsonProperty("referred_binding")
  private String referredBinding = null;

  @JsonProperty("code_challenge")
  private String codeChallenge = null;

  @JsonProperty("code_challenge_method")
  private String codeChallengeMethod = null;

  @JsonProperty("mccmnc")
  private BigDecimal mccmnc = null;

  @JsonProperty("request")
  private String request = null;


  public ServerInitiatedFlowRequestBody baseUrl(String baseUrl) {
    this.baseUrl = baseUrl;
    return this;
  }

  public String getBaseUrl() {
    return baseUrl;
  }
  public void setBaseUrl(String baseUrl) {
    this.baseUrl = baseUrl;
  }


  public ServerInitiatedFlowRequestBody carrierAuthEndpoint(String carrierAuthEndpoint) {
    this.carrierAuthEndpoint = carrierAuthEndpoint;
    return this;
  }

  public String getCarrierAuthEndpoint() {
    return carrierAuthEndpoint;
  }
  public void setCarrierAuthEndpoint(String carrierAuthEndpoint) {
    this.carrierAuthEndpoint = carrierAuthEndpoint;
  }

  public ServerInitiatedFlowRequestBody sdkVersion(String sdkVersion) {
    this.sdkVersion = sdkVersion;
    return this;
  }

  public String getSdkVersion() {
    return sdkVersion;
  }
  public void setSdkVersion(String sdkVersion) {
    this.sdkVersion = sdkVersion;
  }

  public ServerInitiatedFlowRequestBody scope(String scope) {
    this.scope = scope;
    return this;
  }

  public String getScope() {
    return scope;
  }
  public void setScope(String scope) {
    this.scope = scope;
  }


  public ServerInitiatedFlowRequestBody prompt(PromptEnum prompt) {
    this.prompt = prompt;
    return this;
  }

  public PromptEnum getPrompt() {
    return prompt;
  }
  public void setPrompt(PromptEnum prompt) {
    this.prompt = prompt;
  }


  public ServerInitiatedFlowRequestBody responseType(ResponseTypeEnum responseType) {
    this.responseType = responseType;
    return this;
  }

  public ResponseTypeEnum getResponseType() {
    return responseType;
  }
  public void setResponseType(ResponseTypeEnum responseType) {
    this.responseType = responseType;
  }

  public ServerInitiatedFlowRequestBody headerType(HeaderTypeEnum headerType) {
    this.headerType = headerType;
    return this;
  }

  public HeaderTypeEnum getHeaderType() {
    return headerType;
  }
  public void setHeaderType(HeaderTypeEnum headerType) {
    this.headerType = headerType;
  }


  public ServerInitiatedFlowRequestBody clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  public String getClientId() {
    return clientId;
  }
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }


  public ServerInitiatedFlowRequestBody clientNotificationToken(String clientNotificationToken) {
    this.clientNotificationToken = clientNotificationToken;
    return this;
  }

  public String getClientNotificationToken() {
    return clientNotificationToken;
  }
  public void setClientNotificationToken(String clientId) {
    this.clientNotificationToken = clientNotificationToken;
  }


  public ServerInitiatedFlowRequestBody redirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
    return this;
  }

  public String getRedirectUri() {
    return redirectUri;
  }
  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }


  public ServerInitiatedFlowRequestBody state(String state) {
    this.state = state;
    return this;
  }

  public String getState() {
    return state;
  }
  public void setState(String state) {
    this.state = state;
  }


  public ServerInitiatedFlowRequestBody nonce(String nonce) {
    this.nonce = nonce;
    return this;
  }

  public String getNonce() {
    return nonce;
  }
  public void setNonce(String nonce) {
    this.nonce = nonce;
  }


  public ServerInitiatedFlowRequestBody iat(String iat) {
    this.iat = iat;
    return this;
  }

  public String getIat() {
    return iat;
  }
  public void setIat(String iat) {
    this.iat = iat;
  }


  public ServerInitiatedFlowRequestBody sub(String sub) {
    this.sub = sub;
    return this;
  }

  public String getSub() {
    return sub;
  }
  public void setSub(String sub) {
    this.sub = sub;
  }


  public ServerInitiatedFlowRequestBody exp(String exp) {
    this.exp = exp;
    return this;
  }

  public String getExp() {
    return exp;
  }
  public void setExp(String exp) {
    this.exp = exp;
  }


  public ServerInitiatedFlowRequestBody iss(String iss) {
    this.iss = iss;
    return this;
  }

  public String getIss() {
    return iss;
  }
  public void setIss(String iss) {
    this.iss = iss;
  }


  public ServerInitiatedFlowRequestBody aud(String aud) {
    this.aud = aud;
    return this;
  }

  public String getAud() {
    return aud;
  }
  public void setAud(String aud) {
    this.aud = aud;
  }


  public ServerInitiatedFlowRequestBody expiresIn(String expiresIn) {
    this.expiresIn = expiresIn;
    return this;
  }

  public String getExpiresIn() {
    return expiresIn;
  }
  public void setExpiresIn(String expiresIn) {
    this.expiresIn = expiresIn;
  }


  public ServerInitiatedFlowRequestBody jti(String jti) {
    this.jti = jti;
    return this;
  }

  public String getJti() {
    return jti;
  }
  public void setJti(String jti) {
    this.jti = jti;
  }


  public ServerInitiatedFlowRequestBody options(String options) {
    this.options = options;
    return this;
  }

  public String getOptions() {
    return options;
  }
  public void setOptions(String options) {
    this.options = options;
  }


  public ServerInitiatedFlowRequestBody referredBinding(String referredBinding) {
    this.referredBinding = referredBinding;
    return this;
  }

  public String getReferredBinding() {
    return referredBinding;
  }
  public void setReferredBinding(String referredBinding) {
    this.referredBinding = referredBinding;
  }


  public ServerInitiatedFlowRequestBody acrValues(String acrValues) {
    this.acrValues = acrValues;
    return this;
  }

  public String getAcrValues() {
    return acrValues;
  }
  public void setAcrValues(String acrValues) {
    this.acrValues = acrValues;
  }


  public ServerInitiatedFlowRequestBody loginHintToken(String loginHintToken) {
    this.loginHintToken = loginHintToken;
    return this;
  }

  public String getLoginHintToken() {
    return loginHintToken;
  }
  public void setLoginHintToken(String loginHintToken) {
    this.loginHintToken = loginHintToken;
  }


  public ServerInitiatedFlowRequestBody loginHint(String loginHint) {
    this.loginHint = loginHint;
    return this;
  }

  public String getLoginHint() {
    return loginHint;
  }
  public void setLoginHint(String loginHint) {
    this.loginHint = loginHint;
  }

  public ServerInitiatedFlowRequestBody codeChallenge(String codeChallenge) {
    this.codeChallenge = codeChallenge;
    return this;
  }

  public String getCodeChallenge() {
    return codeChallenge;
  }
  public void setCodeChallenge(String codeChallenge) {
    this.codeChallenge = codeChallenge;
  }

  public BigDecimal getMccMnc() {
    return mccmnc;
  }
  public void setMccMnc(BigDecimal mccMnc) {
    this.mccmnc = mccMnc;
  }


  public ServerInitiatedFlowRequestBody codeChallengeMethod(String codeChallengeMethod) {
    this.codeChallengeMethod = codeChallengeMethod;
    return this;
  }

  public String getCodeChallengeMethod() {
    return codeChallengeMethod;
  }
  public void setCodeChallengeMethod(String codeChallengeMethod) {
    this.codeChallengeMethod = codeChallengeMethod;
  }


  public ServerInitiatedFlowRequestBody context(String context) {
    this.context = context;
    return this;
  }

  public String getContext() {
    return context;
  }
  public void setContext(String context) {
    this.context = context;
  }


  public ServerInitiatedFlowRequestBody notificationUri(String notificationUri) {
    this.notificationUri = notificationUri;
    return this;
  }

  public String getNotificationUri() {
    return notificationUri;
  }
  public void setNotificationUri(String notificationUri) {
    this.notificationUri = notificationUri;
  }


  public ServerInitiatedFlowRequestBody correlationId(String correlationId) {
    this.correlationId = correlationId;
    return this;
  }

  public String getCorrelationId() {
    return correlationId;
  }
  public void setCorrelationId(String correlationId) {
    this.correlationId = correlationId;
  }


  public ServerInitiatedFlowRequestBody request(String request) {
    this.request = request;
    return this;
  }

  public String getRequest() {
    return request;
  }
  public void setRequest(String request) {
    this.request = request;
  }
}

