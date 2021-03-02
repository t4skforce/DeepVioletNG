package io.github.t4skforce.deepviolet.protocol.tls.handshake;

public interface TlsHandhake {

  public TlsHandshakeType getType();

  public byte[] getBytes();

}
