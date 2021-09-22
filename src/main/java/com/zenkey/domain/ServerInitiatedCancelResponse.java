package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ServerInitiatedCancelResponse {

    @JsonProperty("auth_req_id")
    private String authReqId = null;

    @JsonProperty("carrier_server_initiated_cancel_endpoint")
    private String carrierSICancelEndpoint = null;

    public ServerInitiatedCancelResponse authReqId(String authReqId) {
        this.authReqId = authReqId;
        return this;
    }

    public ServerInitiatedCancelResponse carrierSICancelEndpoint(String carrierSICancelEndpoint) {
        this.carrierSICancelEndpoint = carrierSICancelEndpoint;
        return this;
    }

    /**
     * Get authReqId
     * @return authReqId
     **/
    public String getAuthReqId() {
        return authReqId;
    }

    public void setAuthReqId(String authReqId) {
        this.authReqId = authReqId;
    }


    /**
     * Get carrierSICancelEndpoint
     * @return carrierSICancelEndpoint
     **/
    public String getCarrierSICancelEndpoint() {
        return carrierSICancelEndpoint;
    }

    public void setCarrierSICancelEndpoint(String carrierSICancelEndpoint) {
        this.carrierSICancelEndpoint = carrierSICancelEndpoint;
    }
}
