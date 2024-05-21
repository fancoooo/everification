package fpt.signature.sign.ex;

public class CodeException extends Exception {

    private int responsecode;

    public CodeException(int errorCode) {
        this.responsecode = errorCode;
    }

    public int getResponsecode() {
        return responsecode;
    }

    public void setResponsecode(int responsecode) {
        this.responsecode = responsecode;
    }
}
