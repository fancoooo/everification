package fpt.signature.sign.service;

import fpt.signature.sign.object.VerifyResult;

import java.util.List;

public interface IEVerifyService {
    public List<VerifyResult> verifyPdf(byte[] data) throws Exception;
}
