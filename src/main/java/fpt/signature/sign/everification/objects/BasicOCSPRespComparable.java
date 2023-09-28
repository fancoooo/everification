package fpt.signature.sign.everification.objects;

import java.util.Date;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

public class BasicOCSPRespComparable implements Comparable<BasicOCSPRespComparable> {
    private BasicOCSPResp basicOCSPResp;

    private Date producedAt;

    public BasicOCSPRespComparable(BasicOCSPResp basicOCSPResp, Date producedAt) {
        this.basicOCSPResp = basicOCSPResp;
        this.producedAt = producedAt;
    }

    public BasicOCSPResp getBasicOCSPResp() {
        return this.basicOCSPResp;
    }

    public void setBasicOCSPResp(BasicOCSPResp basicOCSPResp) {
        this.basicOCSPResp = basicOCSPResp;
    }

    public Date getProducedAt() {
        return this.producedAt;
    }

    public void setProducedAt(Date producedAt) {
        this.producedAt = producedAt;
    }

    public int compareTo(BasicOCSPRespComparable o) {
        if (getProducedAt() == null || o.getProducedAt() == null)
            return 0;
        return getProducedAt().compareTo(o.getProducedAt());
    }
}

