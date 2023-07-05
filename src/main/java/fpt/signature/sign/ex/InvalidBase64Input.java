package fpt.signature.sign.ex;

public class InvalidBase64Input extends Exception {
    public InvalidBase64Input(String message) {
        super(message);
    }
}
