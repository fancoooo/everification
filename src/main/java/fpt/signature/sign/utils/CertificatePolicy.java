package fpt.signature.sign.utils;


import java.security.MessageDigest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

public class CertificatePolicy {
    private static final HashMap<String, String> keyUsages = new HashMap<>();

    private static final HashMap<String, String> certificateFields = new HashMap<>();

    public static final String OID_CN = "2.5.4.3";

    public static final String OID_EMAIL = "1.2.840.113549.1.9.1";

    public static final String OID_UID = "0.9.2342.19200300.100.1.1";

    public static final String OID_PHONE = "2.5.4.20";

    public static final String OID_ST = "2.5.4.8";

    public static final String OID_O = "2.5.4.10";

    public static final String OID_L = "2.5.4.7";

    public static final String OID_OU = "2.5.4.11";

    public static final String OID_T = "2.5.4.12";

    public static final String OID_C = "2.5.4.6";

    public static final String OID_G = "2.5.4.42";

    public static final String SAN_KEY_EMAIL = "rfc822Name";

    public static final String PREFIX_PERSONAL_CODE = "CMND:";

    public static final String PREFIX_PERSONAL_PASSPORT_CODE = "HC:";

    public static final String PREFIX_ENTERPRISE_TAX_CODE = "MST:";

    public static final String PREFIX_ENTERPRISE_BUDGET_CODE = "MNS:";

    public static final String PREFIX_CITIZEN_CODE = "CCCD:";

    public static final String PREFIX_OWNER_PERSONAL_CODE = "PID:";

    public static final String PREFIX_OWNER_PERSONAL_PASSPORT_CODE = "PPID:";

    public static final String PREFIX_OWNER_CITIZEN_CODE = "PEID:";

    public static final String PREFIX_OWNER_ENTERPRISE_TAX_CODE = "TIN:";

    public static final String PREFIX_OWNER_ENTERPRISE_BUDGET_CODE = "BGC:";

    public static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";

    public static final String DEFAULT_FILE_NAME = "undefined";

    private static final String DATEFORMAT = "yyyy-MM-dd HH:mm:ssXXX";

    public static final int USER_DEFINED_INFO_TYPE_PERSONALNAME = 0;

    public static final int USER_DEFINED_INFO_TYPE_COMPANYNAME = 1;

    public static final int USER_DEFINED_INFO_TYPE_PERSONALID = 2;

    public static final int USER_DEFINED_INFO_TYPE_PASSPORTID = 3;

    public static final int USER_DEFINED_INFO_TYPE_TAXID = 4;

    public static final int USER_DEFINED_INFO_TYPE_BUDGETID = 5;

    public static final String CERT_TYPE_PERSONAL = "PERSONAL";

    public static final String CERT_TYPE_ENTERPRISE = "ENTERPRISE";

    public static final String CERT_TYPE_STAFF = "STAFF";

    public static final String REQUEST_TYPE_ISSUE = "ISSUE";

    public static final String REQUEST_TYPE_RENEWAL = "RENEWAL";

    public static final String REQUEST_TYPE_CHANGE_INFO = "CHANGE_INFO";

    static {
        keyUsages.put("1.3.6.1.5.5.7.3.1", "Server Authentication");
        keyUsages.put("1.3.6.1.5.5.7.3.2", "Client Authentication");
        keyUsages.put("1.3.6.1.5.5.7.3.3", "Code Signing");
        keyUsages.put("1.3.6.1.5.5.7.3.4", "Secure Email");
        keyUsages.put("1.3.6.1.5.5.7.3.8", "Time Stamping");
        keyUsages.put("1.3.6.1.5.5.7.3.9", "OCSP Signing");
        certificateFields.put("2.5.4.3", "CN");
        certificateFields.put("1.2.840.113549.1.9.1", "E");
        certificateFields.put("0.9.2342.19200300.100.1.1", "UID");
        certificateFields.put("2.5.4.20", "telephoneNumber");
        certificateFields.put("2.5.4.8", "ST");
        certificateFields.put("2.5.4.10", "O");
        certificateFields.put("2.5.4.7", "L");
        certificateFields.put("2.5.4.11", "OU");
        certificateFields.put("2.5.4.12", "T");
        certificateFields.put("2.5.4.6", "C");
        certificateFields.put("2.5.4.42", "G");
    }

    public static String convertDateToString(Date datetime) {
        String dateString = null;
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssXXX");
            sdf.setTimeZone(TimeZone.getTimeZone(System.getProperty("user.timezone")));
            dateString = sdf.format(datetime);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dateString;
    }

    public static boolean validateCertType(String certType) {
        if (Utils.isNullOrEmpty(certType))
            return false;
        if (!certType.equals("PERSONAL") &&
                !certType.equals("ENTERPRISE") &&
                !certType.equals("STAFF"))
            return false;
        return true;
    }

    public static boolean validateRequestType(String requestType) {
        if (Utils.isNullOrEmpty(requestType))
            return false;
        if (!requestType.equals("ISSUE") &&
                !requestType.equals("RENEWAL") &&
                !requestType.equals("CHANGE_INFO"))
            return false;
        return true;
    }

    public static String[] getPersonAndCompany(String dn, String certType) {
        String[] result = new String[2];
        if (certType.equals("PERSONAL")) {
            result[0] = getCommonName(dn);
            result[1] = null;
        } else if (certType.equals("ENTERPRISE")) {
            result[0] = null;
            result[1] = getCommonName(dn);
        } else {
            result[0] = getCommonName(dn);
            result[1] = getOrganization(dn);
        }
        return result;
    }

    public static String getOrganization(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.10"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getTitle(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.12"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getStateOrProvince(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.8"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getCommonName(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.3"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getEmailFromDn(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("1.2.840.113549.1.9.1"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getGivenName(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.42"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getOrganizationUnit(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.11"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getLocality(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.7"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getCountry(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.6"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getPhoneFromDn(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.20"))
                return attributeTypeAndValue[0].getValue().toString();
        }
        return null;
    }

    public static String getPersonalCode(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        String result = null;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains("CMND:")) {
                result = value.substring("CMND:".length());
                break;
            }
        }
        return result;
    }

    public static String getCitizenCode(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        String result = null;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains("CCCD:")) {
                result = value.substring("CCCD:".length());
                break;
            }
        }
        return result;
    }

    public static String getPassportCode(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        String result = null;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains("HC:")) {
                result = value.substring("HC:".length());
                break;
            }
        }
        return result;
    }

    public static String getTaxCode(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        String result = null;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains("MST:")) {
                result = value.substring("MST:".length());
                break;
            }
        }
        return result;
    }

    public static String getBudgetCode(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        String result = null;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains("MNS:")) {
                result = value.substring("MNS:".length());
                break;
            }
        }
        return result;
    }

    public static String generateCertificateSerialNumber(String prefix) throws Exception {
        String uniqueID = UUID.randomUUID().toString();
        String datetime = String.valueOf(System.currentTimeMillis());
        String randomValue = datetime + uniqueID;
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(randomValue.getBytes());
        String hashed = DatatypeConverter.printHexBinary(md.digest()).toLowerCase();
        String t = prefix + hashed;
        return t.substring(0, 32).toUpperCase();
    }

    public static String getKeyUsage(List<String> extendedKeyUsage, boolean[] keyUsage) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < extendedKeyUsage.size(); i++)
            result.add(keyUsages.get(extendedKeyUsage.get(i)));
        if (keyUsage[0])
            result.add("Digital Signature");
        if (keyUsage[1])
            result.add("Non-Repudiation");
        if (keyUsage[2])
            result.add("Key Encipherment");
        if (keyUsage[3])
            result.add("Data Encipherment");
        if (keyUsage[4])
            result.add("Key Agreement");
        if (keyUsage[5])
            result.add("Key CertSign");
        if (keyUsage[6])
            result.add("CRL Sign");
        if (keyUsage[7])
            result.add("Encipher Only");
        if (keyUsage[8])
            result.add("Decipher Only");
        String tmp = "";
        for (int j = 0; j < result.size(); j++) {
            if (j != result.size() - 1) {
                tmp = tmp + (String)result.get(j) + ", ";
            } else {
                tmp = tmp + (String)result.get(j);
            }
        }
        return tmp;
    }

    public static String generateKeystorePassword(String subjectDn) {
        X500Name subject = new X500Name(subjectDn);
        RDN[] rdn = subject.getRDNs();
        String result = "";
        boolean isSet = false;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains("MST:") || value.contains("MNS:")) {
                if (value.contains("MST:")) {
                    result = value.substring("MST:".length());
                } else {
                    result = value.substring("MNS:".length());
                }
                isSet = true;
            } else if ((value.contains("CMND:") || value
                    .contains("HC:") || value
                    .contains("CCCD:")) &&
                    !isSet) {
                if (value.contains("CMND:")) {
                    result = value.substring("CMND:".length());
                } else if (value.contains("CCCD:")) {
                    result = value.substring("CCCD:".length());
                } else {
                    result = value.substring("HC:".length());
                }
            }
        }
        if (result.equals(""))
            result = "changeit";
        return result;
    }

    public static List<String> getAltNames(X509Certificate certificate, Integer[] nameTypes) {
        if (certificate == null)
            return null;
        List<String> names = new LinkedList<>();
        try {
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            if (altNames != null)
                for (Iterator<List<?>> nameIterator = altNames.iterator(); nameIterator.hasNext(); ) {
                    List<?> altName = (List)nameIterator.next();
                    for (int i = 0; i < nameTypes.length; i++) {
                        if (altName.get(0).equals(nameTypes[i])) {
                            names.add((String)altName.get(1));
                            break;
                        }
                    }
                }
        } catch (CertificateParsingException e1) {
            e1.printStackTrace();
        }
        return names;
    }

    public static HashMap<String, String> getCertificateFields() {
        return certificateFields;
    }

    public static String[] getCertificateInformation(String subjectDn) {
        String organization = getOrganization(subjectDn);
        int i = subjectDn.contains("MNS:") | subjectDn.contains("MST:") == true ? 1 : 0;
        int j = subjectDn.contains("CMND:") | subjectDn.contains("HC:") | subjectDn.contains("CCCD:") == true ? 1 : 0;
        String[] result = new String[7];
        if (Utils.isNullOrEmpty(organization) && i == 0) {
            result[0] = getCommonName(subjectDn);
        } else {
            result[0] = "";
        }
        if (Utils.isNullOrEmpty(result[0]))
            if (j != 0) {
                result[0] = getCommonName(subjectDn);
            } else {
                result[0] = "";
            }
        if (!Utils.isNullOrEmpty(organization)) {
            result[1] = organization;
        } else if (i != 0) {
            result[1] = getCommonName(subjectDn);
        } else {
            result[1] = "";
        }
        if (j != 0) {
            if (subjectDn.contains("CMND:")) {
                int indexFound = subjectDn.indexOf("CMND:");
                String str = subjectDn.substring(indexFound + "CMND:".length());
                int indexEnd = str.indexOf(",");
                if (indexEnd == -1) {
                    result[2] = str;
                } else {
                    result[2] = str.substring(0, indexEnd);
                }
            } else {
                result[2] = "";
            }
        } else {
            result[2] = "";
        }
        if (j != 0) {
            if (subjectDn.contains("HC:")) {
                int indexFound = subjectDn.indexOf("HC:");
                String str = subjectDn.substring(indexFound + "HC:".length());
                int indexEnd = str.indexOf(",");
                if (indexEnd == -1) {
                    result[3] = str;
                } else {
                    result[3] = str.substring(0, indexEnd);
                }
            } else {
                result[3] = "";
            }
        } else {
            result[3] = "";
        }
        if (j != 0) {
            if (subjectDn.contains("CCCD:")) {
                int indexFound = subjectDn.indexOf("CCCD:");
                String str = subjectDn.substring(indexFound + "CCCD:".length());
                int indexEnd = str.indexOf(",");
                if (indexEnd == -1) {
                    result[6] = str;
                } else {
                    result[6] = str.substring(0, indexEnd);
                }
            } else {
                result[6] = "";
            }
        } else {
            result[6] = "";
        }
        if (i != 0) {
            if (subjectDn.contains("MST:")) {
                int indexFound = subjectDn.indexOf("MST:");
                String str = subjectDn.substring(indexFound + "MST:".length());
                int indexEnd = str.indexOf(",");
                if (indexEnd == -1) {
                    result[4] = str;
                } else {
                    result[4] = str.substring(0, indexEnd);
                }
            } else {
                result[4] = "";
            }
        } else {
            result[4] = "";
        }
        if (i != 0) {
            if (subjectDn.contains("MNS:")) {
                int indexFound = subjectDn.indexOf("MNS:");
                String str = subjectDn.substring(indexFound + "MNS:".length());
                int indexEnd = str.indexOf(",");
                if (indexEnd == -1) {
                    result[5] = str;
                } else {
                    result[5] = str.substring(0, indexEnd);
                }
            } else {
                result[5] = "";
            }
        } else {
            result[5] = "";
        }
        return result;
    }

    public static String getCertFileNameFromSubjectDn(String subjectDn) {
        X500Name subject = new X500Name(subjectDn);
        RDN[] rdn = subject.getRDNs();
        String result = "";
        boolean isSet = false;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains("MST:") || value.contains("MNS:")) {
                if (value.contains("MST:")) {
                    result = value.substring("MST:".length());
                } else {
                    result = value.substring("MNS:".length());
                }
                isSet = true;
            } else if ((value.contains("CMND:") || value.contains("HC:")) &&
                    !isSet) {
                if (value.contains("CMND:")) {
                    result = value.substring("CMND:".length());
                } else {
                    result = value.substring("HC:".length());
                }
            }
        }
        if (result.compareTo("") == 0)
            result = UnicodeRemoval.removeAccent(getCommonName(subjectDn));
        return result;
    }
}

