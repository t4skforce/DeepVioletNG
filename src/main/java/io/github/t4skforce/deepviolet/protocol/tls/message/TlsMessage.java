package io.github.t4skforce.deepviolet.protocol.tls.message;

import io.github.t4skforce.deepviolet.protocol.tls.handshake.TlsHandshakeType;

public abstract class TlsMessage {

  public abstract TlsHandshakeType getType();

  public abstract int getLength();

  public abstract byte[] getBytes();

  public abstract boolean isValid();
}
