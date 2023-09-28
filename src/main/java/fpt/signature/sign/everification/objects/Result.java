package fpt.signature.sign.everification.objects;

import java.security.cert.X509Certificate;
import java.util.List;

public class Result {
    private boolean rs;
    private List<X509Certificate> certchain;

    public Result(boolean rs, List<X509Certificate> certchain) {
        this.rs = rs;
        this.certchain = certchain;
    }

    public boolean isValid(){
        return this.rs;
    }

    public List<X509Certificate> getBuiltChain(){
        return this.certchain;
    }
}
