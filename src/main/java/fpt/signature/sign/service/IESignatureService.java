package fpt.signature.sign.service;

public interface IESignatureService {
    public String signPdf(byte[] data) throws Exception;
}
