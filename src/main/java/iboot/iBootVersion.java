package iboot;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.exception.InvalidInputException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

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
            // iPhone
            "m68ap", // iPhone 2G (1,1)
            "n82ap", // iPhone 3G (1,2)
            "n88ap", // iPhone 3GS (2,1)
            "n90ap", // iPhone 4 (3,1)
            "n90bap", // iPhone 4 (3,2)
            "n92ap", // iPhone 4 (3,3)
            "n94ap", // iPhone 4S (4,1)
            "n41ap", // iPhone 5 (5,1)
            "n42ap", // iPhone 5 (5,2)
            "n48ap", // iPhone 5c (5,3)
            "n49ap", // iPhone 5c (5,4)

            // iPod touch
            "n45ap", // iPod touch 1st generation (1,1)
            "n72ap", // iPod touch 2nd generation (2,1)
            "n18ap", // iPod touch 3rd generation (3,1)
            "n81ap", // iPod touch 4th generation (4,1)
            "n78ap", // iPod touch 5th generation (5,1)
            "n78aap", // iPod touch 5th generation (5,1)

            // iPad
            "k48ap", // iPad 1st generation (1,1)
            "k93ap", // iPad 2 (2,1)
            "k94ap", // iPad 2 (2,2)
            "k95ap", // iPad 2 (2,3)
            "k93aap", // iPad 2 (2,4)
            "p105ap", // iPad mini (2,5)
            "p106ap", // iPad mini (2,6)
            "p107ap", // iPad mini (2,7)
            "j1ap", // iPad 3rd generation (3,1)
            "j2ap", // iPad 3rd generation (3,2)
            "j2aap", // iPad 3rd generation (3,3)
            "p101ap", // iPad 4th generation (3,4)
            "p102ap", // iPad 4th generation (3,5)
            "p103ap", // iPad 4th generation (3,6)

            // Apple TV
            "k66ap", // Apple TV 2nd generation (2,1)
            "j33ap", // Apple TV 3rd generation (3,1)
            "j33iap", // Apple TV 3rd generation (3,2)

            // SoCs
            "s5l8900xsi", // ???
            "s5l8720xsi", // ???
            "s5l8920xsi", // ???
            "s5l8922xsi", // ???
            "s5l8930xsi", // A4
            "s5l8940xsi", // A5
            "s5l8942xsi", // A5
            "s5l8945xsi", // A5X
            "s5l8947xsi", // A5
            "s5l8950xsi", // A6
            "s5l8955xsi", // A6X
    };

    private final String description;

    public iBootVersion(ByteProvider provider) throws IOException {
        this.description = new String(provider.readBytes(DESCRIPTION_OFFSET, DESCRIPTION_SIZE),
                StandardCharsets.US_ASCII);
    }

    public String getType() throws InvalidInputException {
        for (String type : TYPES) {
            if (description.startsWith(type + " for ")) {
                return type;
            }
        }
        throw new InvalidInputException();
    }

    public String getDevice() throws InvalidInputException {
        String descriptionWithoutType = this.description.substring((this.getType() + " for ").length());
        return descriptionWithoutType.substring(0, descriptionWithoutType.indexOf(',')).toLowerCase();
    }

    public boolean isSupported() throws InvalidInputException {
        String device = this.getDevice();
        for (String unsupportedDevice : DEVICES_32BIT) {
            if (device.equals(unsupportedDevice)) {
                return false;
            }
        }
        return true;
    }

    public long getBaseAddress() {
        return 0;
    }
}
