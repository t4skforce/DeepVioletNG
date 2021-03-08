package io.github.t4skforce.deepviolet.protocol.tls.message;

import org.apache.commons.lang3.NotImplementedException;

@Deprecated
public class TlsServerHello {

  public TlsServerHello() {
  }

  public byte[] getBytes() {
    throw new NotImplementedException();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private Builder() {
    }

    public TlsServerHello build() {
      return new TlsServerHello();
    }

  }

}
