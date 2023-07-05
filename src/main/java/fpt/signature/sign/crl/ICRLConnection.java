package fpt.signature.sign.crl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import fpt.signature.sign.ex.*;

public interface ICRLConnection {
    CRLCertStatus checkCerCRL(String var1) throws InvalidCerException, ConnectErrorException, NotFoundURL;

    CRLCertStatus checkCerCRL(String var1, String var2, Date var3) throws InvalidCerException, ConnectErrorException, NotFoundURL;

    CRLCertStatus checkCerCRL(X509Certificate var1, String var2, Date var3) throws InvalidCerException, ConnectErrorException, NotFoundURL;

    CRLCertStatus checkCerCRL(ArrayList<X509Certificate> var1, String var2, Date var3) throws InvalidCerException, ConnectErrorException, NotFoundURL;

    CRLCertStatus checkCerCRLFromFile(String var1, String var2, Date var3) throws InvalidCerException, ConnectErrorException, NotFoundURL;

    CRLCertStatus checkCerCRLFromURL(String var1, String var2, String var3) throws InvalidCerException, ConnectErrorException, InvalidBase64Input;

    CRLCertStatus checkCerCRLFromFile(String var1, String var2, String var3) throws InvalidCerException, InvalidBase64Input, NotFoundOrInvalidFormatCRLFile;
}
