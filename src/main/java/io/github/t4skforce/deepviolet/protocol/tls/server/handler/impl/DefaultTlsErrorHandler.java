package io.github.t4skforce.deepviolet.protocol.tls.server.handler.impl;

import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsErrorHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultTlsErrorHandler implements TlsErrorHandler {
  private static final Logger LOG = LoggerFactory.getLogger(DefaultTlsErrorHandler.class);

  @Override
  public void handle(Throwable throwable) {
    LOG.error(throwable.getMessage(), throwable);
  }

}
