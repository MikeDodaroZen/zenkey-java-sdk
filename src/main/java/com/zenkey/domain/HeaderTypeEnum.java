package com.zenkey.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

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
