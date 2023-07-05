package fpt.signature.sign.ocsp;

public enum OCSPResponseCode {
    SUCCESSFUL(0),
    MALFORMED_REQUEST(1),
    INTERNAL_ERROR(2),
    TRY_LATER(3),
    SIG_REQUIRED(5),
    UNAUTHORIZED(6),
    UNKNOWN(-1);

    private int code;

    private OCSPResponseCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }
}
