package fpt.signature.sign.utils;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ConfigFile {
    public static String pathKeyStore;
    public static String passkeySotre;

    static {
        try{
            String folderRuntime = System.getProperty("user.dir");
            System.out.println("folderRuntime: " + folderRuntime);
            Path path = Paths.get(folderRuntime, "config.properties");
            if(!path.toFile().exists())
                throw new Exception("File config not exist!");
            PropertiesConfiguration appConfig = null;
            File f = new File(path.toString());
            if (f.exists() && !f.isDirectory()) {
                try {
                    appConfig = new PropertiesConfiguration(path.toString());
                    pathKeyStore = appConfig.getString("pathKeyStore");
                    passkeySotre = appConfig.getString("passkeySotre");
                } catch (ConfigurationException var5) {
                    var5.printStackTrace();
                }
            }
        }catch (Exception var1){
            System.err.printf("Load config error : " + var1.getMessage());
        }

    }
}
