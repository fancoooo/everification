package fpt.signature.sign.license;

public class BiosManagerFactory {
    public static final String OS_TYPE_WINDOWS = "windows";
    public static final String OS_TYPE_LINUX = "linux";

    public static IBiosManager getInstance(String osType) throws Exception {
        if ("linux".equals(osType)) {
            return new LinuxBiosManager();
        } else if ("windows".equals(osType)) {
            return new WindowsBiosManager();
        } else {
            throw new Exception("Invalid os type");
        }
    }
}
