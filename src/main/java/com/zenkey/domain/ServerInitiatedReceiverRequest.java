package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;
/**
 * Response class to be returned by Api
 * @author pkmst
 *
 */

/**
 * Body7
 */

@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaPKMSTServerCodegen", date = "2019-11-26T22:28:03.257Z")

public class ServerInitiatedReceiverRequest {
    @JsonProperty("auth_req_id")
    private String authReqId = null;

    public ServerInitiatedReceiverRequest authReqId(String authReqId) {
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


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ServerInitiatedReceiverRequest body7 = (ServerInitiatedReceiverRequest) o;
        return Objects.equals(this.authReqId, body7.authReqId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(authReqId);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class Body7 {\n");

        sb.append("    authReqId: ").append(toIndentedString(authReqId)).append("\n");
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
