package fpt.signature.sign.ocsp;

import fpt.signature.sign.ex.ConnectErrorException;
import fpt.signature.sign.ex.InvalidCerException;
import fpt.signature.sign.ex.NotFoundURL;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

public interface IOCSPConnection {
    OCSPCertStatus checkCerOCSP(String var1) throws NotFoundURL, InvalidCerException, ConnectErrorException;

    OCSPCertStatus checkCerOCSP(String var1, Date var2) throws NotFoundURL, InvalidCerException, ConnectErrorException;

    OCSPCertStatus checkCerOCSP(String var1, String var2, Date var3) throws NotFoundURL, InvalidCerException, ConnectErrorException;

    OCSPCertStatus checkCerOCSP(ArrayList<X509Certificate> var1, String var2, Date var3) throws NotFoundURL, InvalidCerException, ConnectErrorException;

    OCSPCertStatus checkCerOCSP(X509Certificate var1, String var2, Date var3) throws NotFoundURL, InvalidCerException, ConnectErrorException;
}
