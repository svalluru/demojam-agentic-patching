// The Applications v2 sample app. Run by systemd with the source launcher, so there is nothing to build:
//
//   PROBES='mina-core=org.apache.mina.core.session.IoSession,...' \
//   java -cp '/opt/apps/<app>/lib/*' /opt/apps/<app>/HealthServer.java
//
// /health reports, for each probed library, the jar its class is loaded from: after a swap it names the
// Lightwell build, so the health check is evidence of the patch, not just of the restart. A class that cannot be
// loaded is reported as "missing" and the server still answers 200: the generated playbook's own checksum check
// is what verifies the jar.
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class HealthServer {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        Map<String, String> jars = new LinkedHashMap<>();
        for (String probe : System.getenv().getOrDefault("PROBES", "").split(",")) {
            String[] kv = probe.trim().split("=", 2);
            if (kv.length != 2) continue;
            try {
                String path = Class.forName(kv[1], false, HealthServer.class.getClassLoader())
                        .getProtectionDomain().getCodeSource().getLocation().getPath();
                jars.put(kv[0], path.substring(path.lastIndexOf('/') + 1));
            } catch (Throwable t) {
                jars.put(kv[0], "missing");
            }
        }
        StringBuilder json = new StringBuilder("{\"status\":\"UP\",\"jars\":{");
        int i = 0;
        for (Map.Entry<String, String> e : jars.entrySet()) {
            json.append(i++ == 0 ? "" : ",").append('"').append(e.getKey()).append("\":\"").append(e.getValue()).append('"');
        }
        byte[] body = json.append("}}").toString().getBytes(StandardCharsets.UTF_8);
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/health", ex -> {
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        server.start();
        System.out.println("listening on " + port + " " + jars);
    }
}
