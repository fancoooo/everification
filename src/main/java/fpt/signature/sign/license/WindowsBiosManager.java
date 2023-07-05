package fpt.signature.sign.license;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Scanner;

public class WindowsBiosManager implements IBiosManager {
    private static final String COMMAND = "wmic bios get serialnumber";
    private static final String KEYWORD = "SerialNumber";
    private static final String COMMAND_CHARACTIS = "wmic bios get BiosCharacteristics";
    private static final String KEYWORD_CHARACTIS = "BiosCharacteristics";

    public String getSerialNumber() {
        return this.getBiosInfo("wmic bios get serialnumber", "SerialNumber");
    }

    public String getBiosCharactis() {
        return this.getBiosInfo("wmic bios get BiosCharacteristics", "BiosCharacteristics");
    }

    private String getBiosInfo(String cmd, String keyword) {
        String sn = "";
        OutputStream os = null;
        InputStream is = null;
        Runtime runtime = Runtime.getRuntime();
        Process process = null;
        String[] command = cmd.split(" ");

        try {
            process = runtime.exec(command);
        } catch (IOException var20) {
            throw new RuntimeException(var20);
        }

        os = process.getOutputStream();
        is = process.getInputStream();

        try {
            os.close();
        } catch (IOException var19) {
            throw new RuntimeException(var19);
        }

        Scanner sc = new Scanner(is);

        try {
            while(sc.hasNext()) {
                String next = sc.next();
                if (!keyword.equals(next)) {
                    sn = sn + next.trim();
                }
            }
        } finally {
            try {
                is.close();
                sc.close();
            } catch (IOException var18) {
                throw new RuntimeException(var18);
            }
        }

        return sn;
    }
}
