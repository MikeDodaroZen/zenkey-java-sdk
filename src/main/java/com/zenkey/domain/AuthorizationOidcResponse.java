package com.zenkey.domain;

import com.fasterxml.jackson.databind.JsonNode;

public class AuthorizationOidcResponse {

    private Boolean isSuccess;
    private Boolean isCarrier;
    private Boolean isCustomerInfoFound;
    private Boolean isRedirectForAuthorization;
    private Boolean isServerInitiated;
    private Boolean isServerInitiatedError;
    private String status;
    private String message;
    private OidcUrlInfo oidcUrlInfo;
    private JsonNode data;
    private String sub;

    public Boolean getIsSuccess() {
        return isSuccess;
    }

    public void setIsSuccess(Boolean success) {
        isSuccess = success;
    }

    public Boolean getIsCarrier() {
        return isCarrier;
    }

    public void setIsCarrier(Boolean carrier) {
        isCarrier = carrier;
    }

    public Boolean getIsCustomerInfoFound() {
        return isCustomerInfoFound;
    }

    public void setIsCustomerInfoFound(Boolean customerInfoFound) {
        isCustomerInfoFound = customerInfoFound;
    }

    public Boolean getIsRedirectForAuthorization() {
        return isRedirectForAuthorization;
    }

    public void setIsRedirectForAuthorization(Boolean redirectForAuthorization) {
        isRedirectForAuthorization = redirectForAuthorization;
    }

    public Boolean getIsServerInitiated() {
        return isServerInitiated;
    }

    public void setIsServerInitiated(Boolean serverInitiated) {
        isServerInitiated = serverInitiated;
    }

    public Boolean getIsServerInitiatedError() {
        return isServerInitiatedError;
    }

    public void setIsServerInitiatedError(Boolean serverInitiatedError) {
        isServerInitiatedError = serverInitiatedError;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public OidcUrlInfo getOidcUrlInfo() {
        return oidcUrlInfo;
    }

    public void setOidcUrlInfo(OidcUrlInfo oidcUrlInfo) {
        this.oidcUrlInfo = oidcUrlInfo;
    }

    public JsonNode getData() {
        return data;
    }

    public void setData(JsonNode data) {
        this.data = data;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }
}
