package fpt.signature.sign.ex;

public class NotFoundAnyKeyUsage extends Exception {
    public NotFoundAnyKeyUsage() {
        super("Not found any Enhanced Key Usage");
    }
}
