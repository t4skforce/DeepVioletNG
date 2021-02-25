package io.github.t4skforce.deepviolet.server;

import io.github.t4skforce.deepviolet.test.extension.SimpleHttpsServer;
import io.github.t4skforce.deepviolet.test.extension.SimpleHttpsServer.KeyStore;
import io.github.t4skforce.deepviolet.test.extension.SimpleHttpsServer.SimpleHttpsServerConfig;
import io.github.t4skforce.deepviolet.test.extension.SimpleHttpsServer.SimpleHttpsServerExtension;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(SimpleHttpsServerExtension.class)
class SimpleHttpsServerTest {

  @Test @SimpleHttpsServerConfig(port = 8000, protocols = {
      "TLSv1" }, key = @KeyStore(value = "server.jks", store = "storepass", key = "keypass"))
  void test(SimpleHttpsServer server) throws Exception {
    System.out.println(server.getUri().toString());
    Thread.sleep(300000);
  }

}
