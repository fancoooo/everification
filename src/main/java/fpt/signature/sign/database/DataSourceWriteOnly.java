package fpt.signature.sign.database;

import fpt.signature.sign.utils.Configuration;
import org.apache.commons.dbcp2.BasicDataSource;

public class DataSourceWriteOnly {
    private static final String DRIVER_CLASS_NAME = Configuration.getInstance().getDbWriteOnlyDriver();

    private static final String DB_URL = Configuration.getInstance().getDbWriteOnlyUrl();

    private static final String DB_USER = Configuration.getInstance().getDbWriteOnlyUsername();

    private static final String DB_PASSWORD = Configuration.getInstance().getDbWriteOnlyPassword();

    private static final int CONN_POOL_SIZE = Configuration.getInstance().getMaxConnection();

    private static final int INIT_CONN = Configuration.getInstance().getInitPoolSize();

    private static final int MIN_IDLE = Configuration.getInstance().getMinPoolIdle();

    private static final int MAX_IDLE = Configuration.getInstance().getMaxPoolIdle();

    private BasicDataSource bds = new BasicDataSource();

    private static fpt.signature.sign.database.DataSourceWriteOnly instance;

    private DataSourceWriteOnly() {
        this.bds.setDriverClassName(DRIVER_CLASS_NAME);
        this.bds.setUrl(DB_URL);
        this.bds.setUsername(DB_USER);
        this.bds.setPassword(DB_PASSWORD);
        this.bds.setInitialSize(INIT_CONN);
        this.bds.setMinIdle(MIN_IDLE);
        this.bds.setMaxIdle(MAX_IDLE);
        this.bds.setMaxTotal(CONN_POOL_SIZE);
        this.bds.setTestWhileIdle(true);
        this.bds.setValidationQuery("SELECT 1;");
        this.bds.setValidationQueryTimeout(1);
        this.bds.setTimeBetweenEvictionRunsMillis(60000L);
        this.bds.setDefaultAutoCommit(Boolean.valueOf(true));
        this.bds.setMaxWaitMillis(3000L);
    }

    public static fpt.signature.sign.database.DataSourceWriteOnly getInstance() {
        if (instance == null){
            return new DataSourceWriteOnly();
        }
        return  instance;
    }

    public BasicDataSource getBds() {
        return this.bds;
    }

    public void setBds(BasicDataSource bds) {
        this.bds = bds;
    }
}
