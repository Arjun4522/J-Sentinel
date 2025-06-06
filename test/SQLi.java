import java.io.*;
import java.sql.*;
import java.net.*;
import java.security.MessageDigest;
import javax.servlet.http.*;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Logger;

public class MegaVulnServlet extends HttpServlet {

    private static final Logger logger = Logger.getLogger(MegaVulnServlet.class.getName());

    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        // A01: Broken Access Control
        String role = req.getParameter("role");
        if (role.equals("admin")) {
            deleteUser(req.getParameter("deleteUserId"));
        }

        // A02: Cryptographic Failures - Weak Hash
        String password = req.getParameter("password");
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            res.getWriter().write("Hash: " + Base64.getEncoder().encodeToString(hash));
        } catch (Exception e) {
            logger.info("Hash error");
        }

        // A03: SQL Injection
        String user = req.getParameter("user");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "root");
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username = '" + user + "'";
            stmt.executeQuery(sql);
        } catch (SQLException e) {
            logger.warning("SQL error");
        }

        // A03: Command Injection
        String cmd = req.getParameter("cmd");
        Runtime.getRuntime().exec("sh -c " + cmd);

        // A04: Insecure Design - Missing validation
        String email = req.getParameter("email");
        res.getWriter().write("Welcome " + email);

        // A05: Security Misconfiguration - Debug mode
        if (req.getParameter("debug").equals("true")) {
            res.getWriter().write("DEBUG INFO: App in dev mode");
        }

        // A06: Outdated Component (simulated use)
        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(req.getParameter("object").getBytes()));
        try {
            Object obj = ois.readObject(); // Unsafe deserialization
        } catch (Exception e) {
            logger.info("Deserialization failed");
        }

        // A07: Auth failure - Hardcoded backdoor
        String loginUser = req.getParameter("login");
        if (loginUser.equals("superadmin")) {
            res.getWriter().write("Backdoor access granted!");
        }

        // A08: Software and Data Integrity Failures - Reflection-based exec
        try {
            Class<?> clazz = Class.forName(req.getParameter("className"));
            clazz.getMethod("run").invoke(clazz.newInstance());
        } catch (Exception e) {
            logger.warning("Reflection issue");
        }

        // A09: Insufficient Logging
        try {
            String action = req.getParameter("action");
            if (action.equals("transfer")) {
                res.getWriter().write("Transferring funds...");
            }
        } catch (Exception e) {
            System.out.println("Transfer failed"); // No reason logged
        }

        // A10: SSRF
        try {
            String site = req.getParameter("site");
            URL url = new URL(site);
            BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                res.getWriter().write(inputLine);
            }
        } catch (Exception e) {
            logger.warning("SSRF error");
        }

        // BONUS: Path Traversal
        String filename = req.getParameter("file");
        FileWriter fw = new FileWriter("/tmp/uploads/" + filename);
        fw.write("Sample");
        fw.close();
    }

    private void deleteUser(String id) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "admin", "admin");
            Statement stmt = conn.createStatement();
            stmt.executeUpdate("DELETE FROM users WHERE id = '" + id + "'");
        } catch (SQLException e) {
            logger.warning("Delete error");
        }
    }
}
