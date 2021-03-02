package io.github.t4skforce.deepviolet.protocol.tls.server.handler.impl;

import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsHelloExchange;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsHelloHandler;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultTlsHelloHandler implements TlsHelloHandler {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultTlsHelloHandler.class);

  @Override
  public void handle(TlsHelloExchange exchange) throws IOException {
    LOG.info(exchange.getClientHello().toString());
  }

}
