// The Applications v2 sample app. Run by systemd with the source launcher, so there is nothing to build:
//
//   java -cp '/opt/apps/sample-app/lib/*' /opt/apps/sample-app/HealthServer.java
//
// It logs through Log4j, so the log4j-core jar in lib/ is genuinely loaded, and /health reports which log4j-core
// jar the running process took its classes from. A swap that left the old jar in use would show here.
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HealthServer {
    private static final Logger LOG = LogManager.getLogger(HealthServer.class);

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        String jar = org.apache.logging.log4j.core.LoggerContext.class
                .getProtectionDomain().getCodeSource().getLocation().getPath();
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/health", ex -> {
            byte[] body = ("{\"status\":\"UP\",\"log4j_core\":\"" + jar.substring(jar.lastIndexOf('/') + 1) + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        server.start();
        LOG.info("sample-app listening on {} with {}", port, jar);
    }
}
