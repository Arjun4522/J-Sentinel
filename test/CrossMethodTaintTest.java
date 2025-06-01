package sentinel.test;

import java.util.logging.Logger;

public class CrossMethodTaintTest {
    private static final Logger logger = Logger.getLogger(CrossMethodTaintTest.class.getName());

    public void start(String userData) {
        String processed = transform(userData);
        logData(processed);
    }

    private String transform(String input) {
        if (input == null) {
            return "default";
        }
        return input.toUpperCase();
    }

    private void logData(String data) {
        logger.info("Data: " + data);
        if (data.length() > 10) {
            logger.warning("Long data: " + data);
        }
    }

    public static void main(String[] args) {
        CrossMethodTaintTest test = new CrossMethodTaintTest();
        String data = args.length > 0 ? args[0] : null;
        test.start(data);
    }
}