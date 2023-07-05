package fpt.signature.sign.ex;

public class ConnectErrorException extends Exception {
    public ConnectErrorException() {
        super("Connect to Server Error, check URL of Connection again!");
    }

    public ConnectErrorException(String message) {
        super(message);
    }
}
