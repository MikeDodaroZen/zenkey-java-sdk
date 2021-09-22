package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ServerInitiatedCancelRequest {

    @JsonProperty("auth_req_id")
    private String authReqId = null;

    public ServerInitiatedCancelRequest authReqId(String authReqId) {
        this.authReqId = authReqId;
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


    @JsonProperty("carrier_server_initiated_cancel_endpoint")
    private String carrierSICancelEndpoint = null;

    public ServerInitiatedCancelRequest carrierSICancelEndpoint(String carrierSICancelEndpoint) {
        this.carrierSICancelEndpoint = carrierSICancelEndpoint;
        return this;
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
