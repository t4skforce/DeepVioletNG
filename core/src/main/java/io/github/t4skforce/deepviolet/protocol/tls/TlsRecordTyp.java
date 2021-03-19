package io.github.t4skforce.deepviolet.protocol.tls;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;

import org.apache.commons.lang3.StringUtils;

@Deprecated
public enum TlsRecordTyp {
  CHANGE_CYPHER_SPEC((byte) 0x14, ""), ALERT((byte) 0x15, ""), HANDSHAKE((byte) 0x16, ""), APPLICATION_DATE((byte) 0x17, ""), HEARTBEAT((byte) 0x18, ""), TLS12_CID((byte) 0x19, "");

  private byte data;
  private String name;

  private TlsRecordTyp(byte data, String name) {
    this.data = data;
    this.name = name;
  }

  public byte getByte() {
    return this.data;
  }

  @JsonValue
  public String getName() {
    return this.name;
  }

  public static TlsRecordTyp of(byte type) {
    for (TlsRecordTyp t : values()) {
      if (t.getByte() == type) {
        return t;
      }
    }
    return null;
  }

  @JsonCreator
  public static TlsRecordTyp of(@JsonProperty("type") String type) {
    for (TlsRecordTyp t : values()) {
      if (StringUtils.equals(t.getName(), type)) {
        return t;
      }
    }
    return null;
  }

  public static boolean isValid(byte type) {
    return of(type) != null;
  }

  @Override
  public String toString() {
    return getName() + "(" + String.format("0x%02X", getByte()) + ")";
  }

}
