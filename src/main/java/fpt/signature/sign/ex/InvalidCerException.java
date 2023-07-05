package fpt.signature.sign.ex;

public class InvalidCerException extends Exception {
    public InvalidCerException() {
        super("Base64 Certificate Input not correct format");
    }

    public InvalidCerException(String message) {
        super(message);
    }
}
