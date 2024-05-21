package fpt.signature.sign.general;


public class RelyingParty {
    public static final int ENTITY_ID = 7;

    public static final int ATTR_CREDENTIAL_TOKEN1 = 27;

    public static final int ATTR_EMAIL_TEMPLATE_OWNER_PASSWORD_NOTIFICATION = 29;

    public static final int ATTR_EMAIL_TEMPLATE_IDENTITY_VERIFICATION = 43;

    public static final int ATTR_MOBILE_TEMPLATE_IDENTITY_VERIFICATION = 44;

    public static final int ATTR_EMAIL_TEMPLATE_VERIFICATION_CHALLENGE = 50;

    public static final int ATTR_MOBILE_TEMPLATE_VERIFICATION_CHALLENGE = 51;

    public static final int ATTR_EMAIL_TEMPLATE_VERIFICATION_OTP = 52;

    public static final int ATTR_MOBILE_TEMPLATE_VERIFICATION_OTP = 53;

    public static final int ATTR_IAM_PROVIDER = 59;

    public static final int ATTR_RELYING_PARTY_LICENSE = 70;

    private int id;

    private boolean authEnabled;

    private AuthPropertiesJSNObject authProperties;
    private String name;

    private IPRestrictionList verificationIPRestriction;

    private FunctionAccessList functionAccessList;
    private VerificationPropertiesJSNObject verificationProperties;


    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }


    public VerificationPropertiesJSNObject getVerificationProperties() {
        return this.verificationProperties;
    }

    public void setVerificationProperties(VerificationPropertiesJSNObject verificationProperties) {
        this.verificationProperties = verificationProperties;
    }

    public IPRestrictionList getVerificationIPRestriction() {
        return this.verificationIPRestriction;
    }

    public void setVerificationIPRestriction(IPRestrictionList verificationIPRestriction) {
        this.verificationIPRestriction = verificationIPRestriction;
    }

    public boolean isAuthEnabled() {
        return authEnabled;
    }

    public void setAuthEnabled(boolean authEnabled) {
        this.authEnabled = authEnabled;
    }

    public AuthPropertiesJSNObject getAuthProperties() {
        return authProperties;
    }

    public void setAuthProperties(AuthPropertiesJSNObject authProperties) {
        this.authProperties = authProperties;
    }

    public FunctionAccessList getFunctionAccessList() {
        return functionAccessList;
    }

    public void setFunctionAccessList(FunctionAccessList functionAccessList) {
        this.functionAccessList = functionAccessList;
    }
}

