package com.test;

import java.io.*;
import java.sql.*;
import java.util.Scanner;

public class App {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        DBHandler.initDatabase();

        System.out.println("Login to the server:");
        System.out.print("Username: ");
        String user = scanner.nextLine();
        System.out.print("Password: ");
        String pass = scanner.nextLine();

        // Vulnerable login
        if (DBHandler.login(user, pass)) {
            System.out.println("Login successful!");

            System.out.print("Enter system command to run: ");
            String cmd = scanner.nextLine();
            CommandExecutor.execute(cmd);
        } else {
            System.out.println("Login failed.");
        }

        scanner.close();
    }
}
