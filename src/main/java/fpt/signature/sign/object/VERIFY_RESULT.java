package fpt.signature.sign.object;

public enum VERIFY_RESULT {
    vefBadInput,
    vefNotFoundBase64CertCorrespond,
    vefValidateFailed,
    vefCantGetRef,
    vefNotFoundCertSigning,
    vefSigSucess,
    vefSigInValid,
    vefCheckCertFailed,
    vefCertNotGood;
}
