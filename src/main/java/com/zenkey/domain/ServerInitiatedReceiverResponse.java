package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Objects;

public class ServerInitiatedReceiverResponse {
    @JsonProperty("auth_req_id")
    private String authReqId = null;

    @JsonProperty("data")
    private JsonNode data = null;

    public ServerInitiatedReceiverResponse authReqId(String authReqId) {
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

    public ServerInitiatedReceiverResponse data(JsonNode data) {
        this.data = data;
        return this;
    }

    /**
     * Get data
     * @return data
     **/
    public JsonNode getData() {
        return data;
    }

    public void setData(JsonNode data) {
        this.data = data;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ServerInitiatedReceiverResponse inlineResponse2004 = (ServerInitiatedReceiverResponse) o;
        return Objects.equals(this.authReqId, inlineResponse2004.authReqId) &&
                Objects.equals(this.data, inlineResponse2004.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(authReqId, data);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class ReceiverSIFGetResponse {\n");

        sb.append("    authReqId: ").append(toIndentedString(authReqId)).append("\n");
        sb.append("    data: ").append(toIndentedString(data)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert the given object to string with each line indented by 4 spaces
     * (except the first line).
     */
    private String toIndentedString(Object o) {
        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n    ");
    }
}
