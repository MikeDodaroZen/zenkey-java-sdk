package com.zenkey.domain;

public class AssertionBody {

    private String iss;
    private String sub;
    private String aud;
    private String jti;
    private int iat;
    private int exp;

    public AssertionBody(String iss, String sub, String aud, String jti, int iat, int exp) {
        this.iss = iss;
        this.sub = sub;
        this.aud = aud;
        this.jti = jti;
        this.iat = iat;
        this.exp = exp;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
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
}
