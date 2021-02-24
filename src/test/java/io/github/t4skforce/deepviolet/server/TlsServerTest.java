package io.github.t4skforce.deepviolet.server;

import io.github.t4skforce.deepviolet.json.TlsVersion;

import javax.net.ssl.SSLContext;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TlsServerTest {

  ServerRunnable server;

  private class ServerRunnable implements Runnable {

    TlsServer server;

    public ServerRunnable() throws Exception {
      server = TlsServer.builder().keyStore("server.jks", "storepass", "keypass")
          .protocols(TlsVersion.of(TlsVersion.TLS_V1).getName()).port(8888).build();
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

    public TlsServer getServer() {
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
    Thread.sleep(300000);
  }

}
