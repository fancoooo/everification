package fpt.signature.sign.utils;

import org.apache.log4j.Logger;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

public class Configuration {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.utils.Configuration.class);

    private static fpt.signature.sign.utils.Configuration instance;

    private Properties prop = new Properties();

    private Properties IdentityDescription = new Properties();

    private Properties VerificationDescription = new Properties();

    private Properties appInfo = new Properties();

    private String dbUrl;

    private String dbUsername;

    private String dbPassword;

    private String dbDriver;

    private String dbReadOnlyUrl;

    private String dbReadOnlyUsername;

    private String dbReadOnlyPassword;

    private String dbReadOnlyDriver;

    private String dbWriteOnlyUrl;

    private String dbWriteOnlyUsername;

    private String dbWriteOnlyPassword;

    private String dbWriteOnlyDriver;

    private int initPoolSize;

    private int minPoolIdle;

    private int maxPoolIdle;

    private int maxConnection = 1;

    private boolean showProcedures;

    private int retry = 1;

    private int appUserDBID = 1;

    private String tmpFmsFolder;

    private byte[] noImage;

    private String neurotechFolder;

    private boolean moduleNeuroTechEnabled;

    private boolean showDebugLog;

    private boolean showInfoLog;

    private boolean showWarnLog;

    private boolean showErrorLog;

    private boolean showFatalLog;

    private String serverTimeType;

    public static fpt.signature.sign.utils.Configuration getInstance() {
        if (instance == null)
            instance = new fpt.signature.sign.utils.Configuration();
        return instance;
    }

    private Configuration() {
        try {
            getEnvConfig();
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            if (Utils.isNullOrEmpty(System.getenv("everify_DB_URL"))) {
                InputStream appProperties = loader.getResourceAsStream("application.properties");
                if (appProperties != null) {
                    this.prop.load(appProperties);
                    if (this.prop.keySet() == null) {
                        String propertiesFile = Utils.getPropertiesFile("application.properties");
                        if (propertiesFile != null) {
                            LOG.info("Read the configuation file from " + propertiesFile);
                            InputStream in = new FileInputStream(propertiesFile);
                            this.prop.load(in);
                            in.close();
                        } else {
                            LOG.error("Cannot find any configuation file. This is a big problem");
                        }
                    }
                    appProperties.close();
                } else {
                    String propertiesFile = Utils.getPropertiesFile("application.properties");
                    if (propertiesFile != null) {
                        LOG.info("Read the configuation file from " + propertiesFile);
                        this.prop.load(new FileInputStream(propertiesFile));
                    } else {
                        LOG.error("Cannot find any configuation file. This is a big problem");
                    }
                }
            } else {
                LOG.debug("Using getenv to obtain configuration values");
            }

            this.dbUrl = (this.prop.getProperty("everify.db.url") == null) ? System.getenv("everify_DB_URL") : this.prop.getProperty("everify.db.url");
            this.dbUsername = (this.prop.getProperty("everify.db.username") == null) ? System.getenv("everify_DB_USERNAME") : this.prop.getProperty("everify.db.username");
            this.dbPassword = (this.prop.getProperty("everify.db.password") == null) ? System.getenv("everify_DB_PASSWORD") : this.prop.getProperty("everify.db.password");
            this.dbDriver = (this.prop.getProperty("everify.db.driver") == null) ? System.getenv("everify_DB_DRIVER") : this.prop.getProperty("everify.db.driver");
            this.dbReadOnlyUrl = (this.prop.getProperty("everify.db.readonly.url") == null) ? System.getenv("everify_DB_READONLY_URL") : this.prop.getProperty("everify.db.readonly.url");
            this.dbReadOnlyUsername = (this.prop.getProperty("everify.db.readonly.username") == null) ? System.getenv("everify_DB_READONLY_USERNAME") : this.prop.getProperty("everify.db.readonly.username");
            this.dbReadOnlyPassword = (this.prop.getProperty("everify.db.readonly.password") == null) ? System.getenv("everify_DB_READONLY_PASSWORD") : this.prop.getProperty("everify.db.readonly.password");
            this.dbReadOnlyDriver = (this.prop.getProperty("everify.db.readonly.driver") == null) ? System.getenv("everify_DB_READONLY_DRIVER") : this.prop.getProperty("everify.db.readonly.driver");
            this.dbWriteOnlyUrl = (this.prop.getProperty("everify.db.writeonly.url") == null) ? System.getenv("everify_DB_WRITEONLY_URL") : this.prop.getProperty("everify.db.writeonly.url");
            this.dbWriteOnlyUsername = (this.prop.getProperty("everify.db.writeonly.username") == null) ? System.getenv("everify_DB_WRITEONLY_USERNAME") : this.prop.getProperty("everify.db.writeonly.username");
            this.dbWriteOnlyPassword = (this.prop.getProperty("everify.db.writeonly.password") == null) ? System.getenv("everify_DB_WRITEONLY_PASSWORD") : this.prop.getProperty("everify.db.writeonly.password");
            this.dbWriteOnlyDriver = (this.prop.getProperty("everify.db.writeonly.driver") == null) ? System.getenv("everify_DB_WRITEONLY_DRIVER") : this.prop.getProperty("everify.db.writeonly.driver");
            this.initPoolSize = Integer.parseInt((this.prop.getProperty("everify.db.init.connection") == null) ? System.getenv("everify_DB_INIT_CONNECTION") : this.prop.getProperty("everify.db.init.connection"));
            this.minPoolIdle = Integer.parseInt((this.prop.getProperty("everify.db.min.idle.connection") == null) ? System.getenv("everify_DB_MIN_IDLE_CONNECTION") : this.prop.getProperty("everify.db.min.idle.connection"));
            this.maxPoolIdle = Integer.parseInt((this.prop.getProperty("everify.db.max.idle.connection") == null) ? System.getenv("everify_DB_MAX_IDLE_CONNECTION") : this.prop.getProperty("everify.db.max.idle.connection"));
            this.maxConnection = Integer.parseInt((this.prop.getProperty("everify.db.max.connection") == null) ? System.getenv("everify_DB_MAX_CONNECTION") : this.prop.getProperty("everify.db.max.connection"));
            this.showProcedures = Boolean.parseBoolean((this.prop.getProperty("everify.db.logging.procedures.enabled") == null) ? System.getenv("everify_DB_LOGGING_PROCEDURES_ENABLED") : this.prop.getProperty("everify.db.logging.procedures.enabled"));
            this.retry = Integer.parseInt((this.prop.getProperty("everify.db.retry") == null) ? System.getenv("everify_DB_RETRY") : this.prop.getProperty("everify.db.retry"));
            this.appUserDBID = Integer.parseInt((this.prop.getProperty("everify.db.app.userid") == null) ? System.getenv("everify_DB_APP_USERID") : this.prop.getProperty("everify.db.app.userid"));
            this.tmpFmsFolder = (this.prop.getProperty("everify.db.app.temp.folder") == null) ? System.getenv("everify_DB_APP_TEMP_FOLDER") : this.prop.getProperty("everify.db.app.temp.folder");
            this.neurotechFolder = (this.prop.getProperty("everify.db.app.neurotech.folder") == null) ? System.getenv("everify_DB_APP_NEUROTECH_FOLDER") : this.prop.getProperty("everify.db.app.neurotech.folder");
            this.moduleNeuroTechEnabled = Boolean.parseBoolean(this.prop.getProperty("everify.module.neurotech.enabled"));
            this.showDebugLog = Boolean.parseBoolean((System.getenv("everify_LOG4J_DEBUG") == null) ? this.prop.getProperty("everify.log4j.debug", "true") : System.getenv("everify_LOG4J_DEBUG"));
            this.showInfoLog = Boolean.parseBoolean((System.getenv("everify_LOG4J_INFO") == null) ? this.prop.getProperty("everify.log4j.info", "true") : System.getenv("everify_LOG4J_INFO"));
            this.showWarnLog = Boolean.parseBoolean((System.getenv("everify_LOG4J_WARN") == null) ? this.prop.getProperty("everify.log4j.warn", "true") : System.getenv("everify_LOG4J_WARN"));
            this.showErrorLog = Boolean.parseBoolean((System.getenv("everify_LOG4J_ERROR") == null) ? this.prop.getProperty("everify.log4j.error", "true") : System.getenv("everify_LOG4J_ERROR"));
            this.showFatalLog = Boolean.parseBoolean((System.getenv("everify_LOG4J_FATAL") == null) ? this.prop.getProperty("everify.log4j.fatal", "true") : System.getenv("everify_LOG4J_FATAL"));
            this.serverTimeType = (this.prop.getProperty("server.time.type") == null) ? System.getenv("SERVER_TIME_TYPE") : this.prop.getProperty("server.time.type");
            if (this.serverTimeType == null)
                this.serverTimeType = "";
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Error while loading app.properties. Details. " + Utils.printStackTrace(e));
        }
    }

    public String getDbUrl() {
        return this.dbUrl;
    }

    public String getDbUsername() {
        return this.dbUsername;
    }

    public String getDbPassword() {
        return this.dbPassword;
    }

    public String getDbDriver() {
        return this.dbDriver;
    }

    public String getDbReadOnlyUrl() {
        return this.dbReadOnlyUrl;
    }

    public String getDbReadOnlyUsername() {
        return this.dbReadOnlyUsername;
    }

    public String getDbReadOnlyPassword() {
        return this.dbReadOnlyPassword;
    }

    public String getDbReadOnlyDriver() {
        return this.dbReadOnlyDriver;
    }

    public String getDbWriteOnlyUrl() {
        return this.dbWriteOnlyUrl;
    }

    public String getDbWriteOnlyUsername() {
        return this.dbWriteOnlyUsername;
    }

    public String getDbWriteOnlyPassword() {
        return this.dbWriteOnlyPassword;
    }

    public String getDbWriteOnlyDriver() {
        return this.dbWriteOnlyDriver;
    }

    public int getInitPoolSize() {
        return this.initPoolSize;
    }

    public int getMinPoolIdle() {
        return this.minPoolIdle;
    }

    public int getMaxPoolIdle() {
        return this.maxPoolIdle;
    }

    public int getMaxConnection() {
        return this.maxConnection;
    }

    public boolean isShowProcedures() {
        return this.showProcedures;
    }

    public int getRetry() {
        return this.retry;
    }

    public Properties getIdentityDescription() {
        return this.IdentityDescription;
    }

    public int getAppUserDBID() {
        return this.appUserDBID;
    }

    public String getTmpFmsFolder() {
        return this.tmpFmsFolder;
    }

    public void setTmpFmsFolder(String tmpFmsFolder) {
        this.tmpFmsFolder = tmpFmsFolder;
    }

    public Properties getAppInfo() {
        return this.appInfo;
    }

    public Properties getVerificationDescription() {
        return this.VerificationDescription;
    }

    public void setVerificationDescription(Properties VerificationDescription) {
        this.VerificationDescription = VerificationDescription;
    }

    public byte[] getNoImage() {
        return this.noImage;
    }

    public String getNeurotechFolder() {
        return this.neurotechFolder;
    }

    public boolean isModuleNeuroTechEnabled() {
        return this.moduleNeuroTechEnabled;
    }

    public boolean isShowDebugLog() {
        return this.showDebugLog;
    }

    public boolean isShowInfoLog() {
        return this.showInfoLog;
    }

    public boolean isShowWarnLog() {
        return this.showWarnLog;
    }

    public boolean isShowErrorLog() {
        return this.showErrorLog;
    }

    public boolean isShowFatalLog() {
        return this.showFatalLog;
    }

    private void getEnvConfig() {
        LOG.info("Load System env:");
        System.getenv().forEach((k, v) -> LOG.info("\t" + k + ":" + v));
    }

    public String getServerTimeType() {
        return this.serverTimeType;
    }
}

