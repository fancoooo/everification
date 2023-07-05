package fpt.signature.sign.object;

public enum ValidateStatus {
    GOOD,
    UNKNOW,
    EXPIRED,
    NOT_YET_VALID,
    REVOKED,
    NOT_KEY_USAGE,
    CAN_NOT_CHECK_REVOCATION,
    CERT_NOT_TRUSTED;
}
