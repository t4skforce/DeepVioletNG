package io.github.t4skforce.deepviolet.protocol.tls.handshake;

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
@Deprecated
public enum TlsHandshakeType {
  HELLO_REQUEST((byte) 0x00, "Hello Request"), CLIENT_HELLO((byte) 0x01, "Client Hello"), SERVER_HELLO((byte) 0x02, "Server Hello"), HELLO_RETRY_REQUEST((byte) 0x06, "Hello Retry Request"),
  CERTIFICATE((byte) 0x0B, "Certificate"), SERVER_KEY_EXCHANGE((byte) 0x0C, "Server Key Exchange"), CERTIFICATE_REQUEST((byte) 0x0D, "Certificate Request"),
  SERVER_HELLO_DONE((byte) 0x0E, "Server Hello Done"), CERTIFICATE_VERIFY((byte) 0x0F, "Certificate Verify"), CLIENT_KEY_EXCHANGE((byte) 0x10, "Client Key Exchange"),
  FINISHED((byte) 0x14, "Finished");

  private byte data;
  private String name;

  private TlsHandshakeType(byte data, String name) {
    this.data = data;
    this.name = name;
  }

  public byte getByte() {
    return this.data;
  }

  public String getName() {
    return this.name;
  }

  public static TlsHandshakeType of(byte[] data) {
    return of(data[0]);
  }

  public static TlsHandshakeType of(byte[] data, int offset) {
    return of(data[offset]);
  }

  public static TlsHandshakeType of(byte type) {
    for (TlsHandshakeType t : values()) {
      if (t.getByte() == type) {
        return t;
      }
    }
    return null;
  }

  @Override
  public String toString() {
    return getName() + "(" + String.format("0x%02X", getByte()) + ")";
  }
}
