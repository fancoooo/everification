package fpt.signature.sign.service.imp;

import fpt.signature.sign.core.PdfSigner;
import keystore.KeyAndCertChain;
import keystore.KeystoreFactory;
import fpt.signature.sign.service.IESignatureService;
import fpt.signature.sign.utils.Base64Utils;
import fpt.signature.sign.utils.HashUtils;
import org.springframework.stereotype.Service;

@Service
public class ESignatureService implements IESignatureService {

    @Override
    public String signPdf(byte[] data) throws Exception {

        // Get private key and certificate from file p12 keystore
        KeyAndCertChain keyandcerts = KeystoreFactory.getPrivateKeyAndCertChain();

        PdfSigner signer = new PdfSigner(data);
        signer._signer =  keyandcerts.getmCertificate();
        signer._certChain =  keyandcerts.getmCertificateChain();

        signer._renderMode = PdfSigner.RenderMode.TEXT_WITH_LOGO_LEFT;
        signer._borderType = PdfSigner.VisibleSigBorder.NONE;
        signer.setFontSize(7);
        signer.setVisibleSignature("LAST", "0,0,200,50");
        signer._reason = "Ký số";
        signer._location = "Hồ Chí Minh";


        // gen PDF to Hash
        byte[] hash = signer.getSecondHash();

        byte[] signed = signer.Sign(HashUtils.signHash(hash, keyandcerts.getmPrivateKey()));
        return Base64Utils.base64Encode(signed);
    }
}
