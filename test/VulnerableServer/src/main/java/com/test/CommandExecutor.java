package com.test;

import java.io.*;

public class CommandExecutor {
    // Command Injection vulnerability
    public static void execute(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader =
                new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null)
                System.out.println(line);
            process.waitFor();
        } catch (Exception e) {
            System.err.println("Command execution failed: " + e.getMessage());
        }
    }
}
