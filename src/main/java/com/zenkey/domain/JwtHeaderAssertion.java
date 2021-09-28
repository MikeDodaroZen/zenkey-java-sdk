package com.zenkey.domain;

public class JwtHeaderAssertion {

    private String alg;
    private String typ;
    private String kid;

    public JwtHeaderAssertion(String alg, String typ, String kid) {
        this.alg = alg;
        this.typ = typ;
        this.kid = kid;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getTyp() {
        return typ;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }
}
