package io.github.t4skforce.deepviolet.protocol.tls.server.handler;

import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;

import java.io.IOException;

public interface TlsErrorHandler {

  public default void handle(TlsProtocolException exception) {
    handle((Throwable) exception);
  }

  public default void handle(IOException exception) {
    handle((Throwable) exception);
  }

  public default void handle(AssertionError exception) {
    handle((Throwable) exception);
  }

  public default void handle(Exception exception) {
    handle((Throwable) exception);
  }

  public abstract void handle(Throwable throwable);

}
