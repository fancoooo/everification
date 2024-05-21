package fpt.signature.sign.auth;

public class AuthVerificationRequest {
    private String rp_id;
    private String rp_pw;

    public String getRp_id() {
        return rp_id;
    }

    public void setRp_id(String rp_id) {
        this.rp_id = rp_id;
    }

    public String getRp_pw() {
        return rp_pw;
    }

    public void setRp_pw(String rp_pw) {
        this.rp_pw = rp_pw;
    }
}
