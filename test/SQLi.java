import java.io.*;
import java.sql.*;
import javax.servlet.http.*;

public class TaintTestSuite extends HttpServlet {

    // SOURCE: HttpServletRequest input
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String userInput = req.getParameter("input");  // SOURCE

        // SINK: Print (CWE-117)
        System.out.println("User input: " + userInput);  // SINK

        // SINK: SQL Injection (CWE-89)
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE username = '" + userInput + "'";
        stmt.executeQuery(sql);  // SINK

        // Sanitized SQL query (safe path)
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        ps.setString(1, userInput); // Should NOT trigger taint
        ps.executeQuery();

        // Command Injection (CWE-78)
        Runtime.getRuntime().exec("echo " + userInput);  // SINK

        // File write (CWE-73 Path Traversal)
        FileWriter fw = new FileWriter("files/" + userInput);  // SINK
        fw.write("tainted content");
        fw.close();

        // Reflection
        try {
            Class.forName(userInput);  // SINK: Dynamic class loading
        } catch (ClassNotFoundException e) {}

        // Deserialization (CWE-502)
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(userInput.getBytes()));
        try {
            Object o = ois.readObject();  // SINK
        } catch (Exception e) {}

        // Propagation through method
        methodSink(directFlow(userInput));

        // Sanitization example
        String cleanInput = sanitize(userInput);
        Statement safeStmt = conn.createStatement();
        safeStmt.executeQuery("SELECT * FROM safe WHERE col = '" + cleanInput + "'");  // should NOT trigger
    }

    // SOURCE: args from main()
    public static void main(String[] args) throws Exception {
        String cliInput = args[0];  // SOURCE
        new TaintTestSuite().sink(cliInput);
    }

    void sink(String input) throws Exception {
        System.out.println("CLI: " + input); // SINK
        Runtime.getRuntime().exec("ping " + input);  // SINK
    }

    String directFlow(String data) {
        return data;
    }

    void methodSink(String val) throws Exception {
        Runtime.getRuntime().exec("echo " + val);  // SINK
    }

    String sanitize(String input) {
        // basic sanitization example
        return input.replaceAll("[^a-zA-Z0-9]", "");
    }

    Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass");
    }
}
