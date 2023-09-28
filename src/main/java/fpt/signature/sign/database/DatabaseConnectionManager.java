package fpt.signature.sign.database;

import fpt.signature.sign.utils.Configuration;
import org.apache.commons.dbcp2.BasicDataSource;
import org.apache.log4j.Logger;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicInteger;

public class DatabaseConnectionManager {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.database.DatabaseConnectionManager.class);

    private static fpt.signature.sign.database.DatabaseConnectionManager instance;

    public static fpt.signature.sign.database.DatabaseConnectionManager getInstance() {
        if (instance == null)
            instance = new fpt.signature.sign.database.DatabaseConnectionManager();
        return instance;
    }

    private final AtomicInteger activeSessions = new AtomicInteger(0);

    private final String readOnlyUrl;

    private final String readOnlyUsername;

    private final String readOnlyPassword;

    private final String writeOnlyUrl;

    private final String writeOnlyUsername;

    private final String writeOnlyPassword;

    private DatabaseConnectionManager() {
        this.readOnlyUrl = Configuration.getInstance().getDbReadOnlyUrl();
        this.readOnlyUsername = Configuration.getInstance().getDbReadOnlyUsername();
        this.readOnlyPassword = Configuration.getInstance().getDbReadOnlyPassword();
        this.writeOnlyUrl = Configuration.getInstance().getDbWriteOnlyUrl();
        this.writeOnlyUsername = Configuration.getInstance().getDbWriteOnlyUsername();
        this.writeOnlyPassword = Configuration.getInstance().getDbWriteOnlyPassword();
    }

    public Connection openConnectionUsingDataSource() {
        Connection conn = null;
        try {
            BasicDataSource bds = DataSource.getInstance().getBds();
            conn = bds.getConnection();
        } catch (Exception e) {
            LOG.error("Cannot open new connection. Details: " + e.toString());
            e.printStackTrace();
        }
        return conn;
    }

    public Connection openReadOnlyConnection() {
        if (this.readOnlyUrl == null || this.readOnlyUsername == null || this.readOnlyPassword == null)
            return openConnectionUsingDataSource();
        Connection conn = null;
        try {
            BasicDataSource bds = DataSourceReadOnly.getInstance().getBds();
            conn = bds.getConnection();
        } catch (Exception e) {
            LOG.error("Cannot open new connection. Details: " + e.toString());
            e.printStackTrace();
        }
        return conn;
    }

    public Connection openWriteOnlyConnection() {
        if (this.writeOnlyUrl == null || this.writeOnlyUsername == null || this.writeOnlyPassword == null)
            return openConnectionUsingDataSource();
        Connection conn = null;
        try {
            BasicDataSource bds = DataSourceWriteOnly.getInstance().getBds();
            conn = bds.getConnection();
        } catch (Exception e) {
            LOG.error("Cannot open new connection. Details: " + e.toString());
            e.printStackTrace();
        }
        return conn;
    }

    public void close(Connection connection) {
        if (connection != null)
            try {
                connection.close();
                this.activeSessions.decrementAndGet();
            } catch (SQLException e) {
                LOG.error("Cannot close connection. Details: " + e.toString());
                e.printStackTrace();
            }
    }
}