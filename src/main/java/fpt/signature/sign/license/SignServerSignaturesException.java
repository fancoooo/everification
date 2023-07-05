package fpt.signature.sign.license;

public class SignServerSignaturesException extends Exception {
    private static final long serialVersionUID = -3903529918407257410L;

    public SignServerSignaturesException(String message) {
        super(message);
    }

    public SignServerSignaturesException(String message, Throwable e) {
        super(message, e);
    }
}
