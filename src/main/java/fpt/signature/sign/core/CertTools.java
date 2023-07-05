package fpt.signature.sign.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.*;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;


public class CertTools {
    public static URL getCrlDistributionPoint(Certificate certificate) throws CertificateParsingException {
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate)certificate;

            try {
                ASN1Object obj = getExtensionValue(x509cert, Extension.cRLDistributionPoints);
                if (obj == null) {
                    return null;
                }

                ASN1Sequence distributionPoints = (ASN1Sequence)obj;

                for(int i = 0; i < distributionPoints.size(); ++i) {
                    ASN1Sequence distrPoint = (ASN1Sequence)distributionPoints.getObjectAt(i);

                    for(int j = 0; j < distrPoint.size(); ++j) {
                        ASN1TaggedObject tagged = (ASN1TaggedObject)distrPoint.getObjectAt(j);
                        if (tagged.getTagNo() == 0) {
                            String url = getStringFromGeneralNames(tagged.getObject());
                            if (url != null) {
                                return new URL(url);
                            }
                        }
                    }
                }
            } catch (Exception var9) {
                throw new CertificateParsingException(var9.toString());
            }
        }

        return null;
    }

    private static String getEnterpriseID(X509Certificate cert) {
        String result = "NULL";
        if (cert != null) {
            X500Name subject = new X500Name(cert.getSubjectDN().toString());
            RDN[] rdn = subject.getRDNs();

            for(int j = 0; j < rdn.length; ++j) {
                AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
                String value = attributeTypeAndValue[0].getValue().toString();
                if (value.contains("MST:")) {
                    result = value.substring("MST:".length());
                    break;
                }

                if (value.contains("MNS:")) {
                    result = value.substring("MNS:".length());
                    break;
                }
            }
        }

        return result;
    }

    public static String getCommonName(X509Certificate cert) throws CertificateEncodingException {
        X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];

        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    private static String getPersonalID(X509Certificate cert) {
        String result = "NULL";
        if (cert != null) {
            X500Name subject = new X500Name(cert.getSubjectDN().toString());
            RDN[] rdn = subject.getRDNs();

            for(int j = 0; j < rdn.length; ++j) {
                AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
                String value = attributeTypeAndValue[0].getValue().toString();
                if (value.contains("CMND:")) {
                    result = value.substring("CMND:".length());
                    break;
                }

                if (value.contains("HC:")) {
                    result = value.substring("HC:".length());
                    break;
                }

                if (value.contains("CCCD:")) {
                    result = value.substring("CCCD:".length());
                    break;
                }
            }
        }

        return result;
    }

    protected static ASN1Object getExtensionValue(X509Certificate cert, ASN1ObjectIdentifier oid) throws IOException {
        if (cert == null) {
            return null;
        } else {
            byte[] bytes = cert.getExtensionValue(oid.getId());
            if (bytes == null) {
                return null;
            } else {
                ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
                ASN1OctetString octs = (ASN1OctetString)aIn.readObject();
                aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
                return aIn.readObject();
            }
        }
    }

    public static X509Certificate StringToX509Certificate(String cer) {
        X509Certificate certificate = null;

        try {
            byte[] cerbytes = Base64.getDecoder().decode(cer);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cerbytes));
            return certificate;
        } catch (CertificateException var4) {
            return null;
        }
    }

    private static String getStringFromGeneralNames(ASN1Object names) {
        ASN1Sequence namesSequence = ASN1Sequence.getInstance((ASN1TaggedObject)names, false);
        if (namesSequence.size() == 0) {
            return null;
        } else {
            DERTaggedObject taggedObject = (DERTaggedObject)namesSequence.getObjectAt(0);
            return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets());
        }
    }
}
