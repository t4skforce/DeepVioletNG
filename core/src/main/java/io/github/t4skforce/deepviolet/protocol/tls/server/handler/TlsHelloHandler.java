package io.github.t4skforce.deepviolet.protocol.tls.server.handler;

import java.io.IOException;

public interface TlsHelloHandler {

  public abstract void handle(TlsHelloExchange exchange) throws IOException;

}
