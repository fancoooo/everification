package fpt.signature.sign.tsa;

public class DataR {
    public String timestampToken;

    public DataR(String timestampToken, String timestamp, String algorithm) {
        this.timestampToken = timestampToken;
        this.timestamp = timestamp;
        this.algorithm = algorithm;
    }

    public String timestamp;
    public String algorithm;
}
