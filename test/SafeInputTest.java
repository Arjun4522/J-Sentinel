package sentinel.test;

import java.util.logging.Logger;

public class SafeInputTest {
    private static final Logger logger = Logger.getLogger(SafeInputTest.class.getName());

    public void processSafeInput(String userInput) {
        if (userInput == null || userInput.isEmpty()) {
            logger.info("Invalid input");
            return;
        }
        // Sanitize input
        String sanitized = userInput.replaceAll("[^a-zA-Z0-9]", "");
        if (sanitized.length() > 0) {
            logger.info("Sanitized: " + sanitized);
        } else {
            logger.warning("No valid characters");
        }
    }

    public static void main(String[] args) {
        SafeInputTest test = new SafeInputTest();
        String input = args.length > 0 ? args[0] : "";
        test.processSafeInput(input);
    }
}