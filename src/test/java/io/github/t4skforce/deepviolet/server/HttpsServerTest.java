package io.github.t4skforce.deepviolet.server;

import javax.net.ssl.SSLContext;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class HttpsServerTest {

  ServerRunnable server;

  private class ServerRunnable implements Runnable {

    HttpsServer server;

    public ServerRunnable() throws Exception {
      server = HttpsServer.builder().keyStore("server.jks", "storepass", "keypass").port(8888)
          .build(); // .protocols(TlsVersion.of(TlsVersion.TLS_V1).getName())
    }

    @Override
    public void run() {
      try {
        server.start();
      } catch (Exception e) {
        e.printStackTrace();
        System.out.println("Server down....");
      }
    }

    public HttpsServer getServer() {
      return server;
    }

    public void stop() {
      if (server != null) {
        server.stop();
      }
    }
  }

  @AfterEach
  void stop() {
    server.stop();
  }

  @Test
  void test() throws Exception {
    System.out.println("protocols: " + StringUtils
        .join(SSLContext.getDefault().createSSLEngine().getSupportedProtocols(), ", "));
    System.out.println("suites: " + StringUtils
        .join(SSLContext.getDefault().createSSLEngine().getSupportedCipherSuites(), ", "));
    server = new ServerRunnable();
    Thread thread = new Thread(server);
    thread.start();
    System.out.println(server.getServer().getHostAddress() + ":" + server.getServer().getPort());
    Thread.sleep(3000000);
    // curl -vvv -k --header "Content-Type: application/json" -X POST --data
    // '{"username":"xyz","password":"xyz"}' https://localhost:8888/api/login
  }

}
