package iboot;

import ghidra.app.util.bin.ByteProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class iBootVersion {
    private static final long DESCRIPTION_OFFSET = 0x200;
    private static final int DESCRIPTION_SIZE = 0x40;

    private static final String[] TYPES = new String[] {
            "SecureROM",
            "LLB",
            "iBoot",
            "iBEC",
            "iBSS"
    };

    private static final String[] DEVICES_32BIT = new String[] {

    };

    private final String description;

    public iBootVersion(ByteProvider provider) throws IOException {
        this.description = new String(provider.readBytes(DESCRIPTION_OFFSET, DESCRIPTION_SIZE),
                StandardCharsets.US_ASCII);
    }

    public String getType() {
        for (String type : TYPES) {
            if (description.startsWith(type + " for ")) {
                return type;
            }
        }
        return "";
    }

    public String getDevice() {
        String descriptionWithoutType = this.description.substring((this.getType() + " for ").length());
        return descriptionWithoutType.substring(0, descriptionWithoutType.indexOf(',')).toLowerCase();
    }

    public int getBitness() {
        return 0;
    }
}
