package sentinel.test;

import java.io.*;
import java.util.logging.*;

public class SimpleTest {
    private static final Logger logger = Logger.getLogger(SimpleTest.class.getName());

    public void run(String userInput) {
        logger.info("Processing input: " + userInput);

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            String line = reader.readLine();
            if (line != null) {
                process(line);
            }
        } catch (IOException ex) {
            logger.severe("Error: " + ex.getMessage());
        } finally {
            logger.info("Operation complete.");
        }
    }

    public void process(String input) {
        if ("start".equals(input)) {
            logger.info("Started: " + input);
        } else {
            logger.warning("Invalid input: " + input);
        }
    }

    public static void main(String[] args) {
        SimpleTest test = new SimpleTest();
        test.run(args.length > 0 ? args[0] : "default");
    }
}