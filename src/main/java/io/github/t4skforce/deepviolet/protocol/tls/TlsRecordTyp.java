package io.github.t4skforce.deepviolet.protocol.tls;

public enum TlsRecordTyp {
  HANDHAKE((byte) 0x16, "Handshake"), CHANGE_CYPHER_SPEC((byte) 0x14, "Change Cipher Spec"),
  ALERT((byte) 0x15, "Alert"), APPLICATION_DATE((byte) 0x17, "Application Data");

  private byte data;
  private String name;

  private TlsRecordTyp(byte data, String name) {
    this.data = data;
    this.name = name;
  }

  public byte getByte() {
    return this.data;
  }

  public String getName() {
    return this.name;
  }

  public static TlsRecordTyp of(byte[] data) {
    return of(data[0]);
  }

  public static TlsRecordTyp of(byte type) {
    for (TlsRecordTyp t : values()) {
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
