package fpt.signature.sign.everification.objects;

import java.security.cert.X509CRL;
import java.util.Date;

public class X509CRLComparable implements Comparable<X509CRLComparable> {
    private X509CRL x509Crl;

    private Date thisUpate;

    public X509CRLComparable(X509CRL x509Crl, Date thisUpate) {
        this.x509Crl = x509Crl;
        this.thisUpate = thisUpate;
    }

    public X509CRL getX509Crl() {
        return this.x509Crl;
    }

    public void setX509Crl(X509CRL x509Crl) {
        this.x509Crl = x509Crl;
    }

    public Date getThisUpate() {
        return this.thisUpate;
    }

    public void setThisUpate(Date thisUpate) {
        this.thisUpate = thisUpate;
    }

    public int compareTo(X509CRLComparable o) {
        if (getThisUpate() == null || o.getThisUpate() == null)
            return 0;
        return getThisUpate().compareTo(o.getThisUpate());
    }
}

