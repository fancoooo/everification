package fpt.signature.sign.ex;

public class NotFoundSignature extends Exception {
    public NotFoundSignature() {
        super("Not found signature in data");
    }
}
