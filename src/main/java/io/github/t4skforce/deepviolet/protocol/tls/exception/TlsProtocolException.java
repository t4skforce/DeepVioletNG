package io.github.t4skforce.deepviolet.protocol.tls.exception;

@Deprecated
public class TlsProtocolException extends Exception {
  private static final long serialVersionUID = -3084554435617469759L;

  public TlsProtocolException() {
    super();
  }

  public TlsProtocolException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public TlsProtocolException(String message, Throwable cause) {
    super(message, cause);
  }

  public TlsProtocolException(String message) {
    super(message);
  }

  public TlsProtocolException(Throwable cause) {
    super(cause);
  }

}
