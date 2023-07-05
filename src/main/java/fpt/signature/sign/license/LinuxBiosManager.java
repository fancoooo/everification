package fpt.signature.sign.license;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import org.apache.log4j.Logger;

public class LinuxBiosManager implements IBiosManager {
    public String getSerialNumber() {
        String sn = null;

        try {
            sn = readSerial();
        } catch (RuntimeException var3) {
        }

        if (sn == null) {
            sn = readLshal();
        }

        if (sn == null) {
            throw new RuntimeException("Cannot find computer SN");
        } else {
            return sn;
        }
    }

    private static BufferedReader read(String command) {
        OutputStream os = null;
        InputStream is = null;
        Runtime runtime = Runtime.getRuntime();
        Process process = null;

        try {
            process = runtime.exec(command.split(" "));
        } catch (IOException var7) {
            throw new RuntimeException(var7);
        }

        os = process.getOutputStream();
        is = process.getInputStream();

        try {
            os.close();
        } catch (IOException var6) {
            throw new RuntimeException(var6);
        }

        return new BufferedReader(new InputStreamReader(is));
    }

    private static String readDmidecode() {
        String sn = "";
        String line = null;
        String marker = "Serial Number:";
        BufferedReader br = null;

        try {
            br = read("dmidecode -t system");

            while(true) {
                if ((line = br.readLine()) != null) {
                    if (line.indexOf(marker) == -1) {
                        continue;
                    }

                    sn = line.split(marker)[1].trim();
                }

                Logger.getLogger(LinuxBiosManager.class).info("Serial Number: " + sn);
                return sn;
            }
        } catch (IOException var12) {
            throw new RuntimeException(var12);
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException var11) {
                    throw new RuntimeException(var11);
                }
            }

        }
    }

    private static String readSerial() {
        BufferedReader br = null;
        String line = "";

        String var2;
        try {
            br = read("dmidecode -s system-serial-number");
            if ((line = br.readLine()) == null) {
                return null;
            }

            Logger.getLogger(LinuxBiosManager.class).info("Serial: " + line);
            var2 = line;
        } catch (IOException var13) {
            Logger.getLogger(LinuxBiosManager.class).warn("Serial Number: " + var13.getMessage());
            return null;
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException var12) {
                }
            }

        }

        return var2;
    }

    private static String readLshal() {
        String sn = "";
        String line = null;
        String marker = "system.hardware.serial =";
        BufferedReader br = null;

        try {
            br = read("lshal");

            while((line = br.readLine()) != null) {
                if (line.indexOf(marker) != -1) {
                    sn = line.split(marker)[1].replaceAll("\\(string\\)|(\\')", "").trim();
                    break;
                }
            }
        } catch (IOException var12) {
            throw new RuntimeException(var12);
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException var11) {
                    throw new RuntimeException(var11);
                }
            }

        }

        return sn;
    }

    public String getBiosCharactis() {
        return "Linux-1.2.6.1.3.8";
    }
}
