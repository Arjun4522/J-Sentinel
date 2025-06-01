package sentinel.test;

import java.io.*;
import java.util.logging.Logger;

public class FileReadTaintTest {
    private static final Logger logger = Logger.getLogger(FileReadTaintTest.class.getName());

    public void readAndProcess(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line = reader.readLine();
            if (line != null) {
                logger.info("Read from file: " + line);
                writeToLogFile(line);
            }
        } catch (IOException e) {
            logger.severe("IO Error: " + e.getMessage());
        }
    }

    private void writeToLogFile(String content) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("output.log", true))) {
            writer.println("Log: " + content);
        } catch (IOException e) {
            logger.warning("Write error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        FileReadTaintTest test = new FileReadTaintTest();
        String path = args.length > 0 ? args[0] : "input.txt";
        test.readAndProcess(path);
    }
}