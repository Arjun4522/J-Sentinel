package com.test;

import java.sql.*;

public class DBHandler {
    private static final String JDBC_URL = "jdbc:h2:mem:testdb";
    private static final String USER = "sa";
    private static final String PASS = "";

    public static void initDatabase() throws SQLException {
        Connection conn = DriverManager.getConnection(JDBC_URL, USER, PASS);
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE users (username VARCHAR(50), password VARCHAR(50))");
        stmt.execute("INSERT INTO users VALUES ('admin', 'admin123')");
        stmt.close();
        conn.close();
    }

    // SQL Injection vulnerable login
    public static boolean login(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection(JDBC_URL, USER, PASS);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        boolean loggedIn = rs.next();
        rs.close();
        stmt.close();
        conn.close();
        return loggedIn;
    }
}
