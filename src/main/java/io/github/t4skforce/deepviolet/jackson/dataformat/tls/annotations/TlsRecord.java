package io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations;

import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.apache.commons.lang3.StringUtils;

/**
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5 https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html
 * https://tools.ietf.org/html/rfc5246#page-37
 *
 */

@Documented
@Target({ ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@JacksonAnnotationsInside
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonPropertyOrder(value = { "type", "protocol", "length", "message" })
public @interface TlsRecord {

  public static final int HEADER_LENGTH = 5;
  public static final int MAX_SIZE = 16384;

  public abstract class Fields {
    public static final String TYPE = "type";
    public static final String PROTOCOL = "protocol";
    public static final String LENGTH = "length";
    public static final String MESSAGE = "message";
  }

  public abstract class Name {
    public static final String HANDSHAKE = "Handshake";
    public static final String CHANGE_CYPHER_SPEC = "ChangeCipherSpec";
    public static final String ALERT = "Alert";
    public static final String APPLICATION_DATA = "ApplicationData";
    public static final String HEARTBEAT = "Heartbeat";
    public static final String TLS12_CID = "TLS12_CID";
    public static final String UNASSIGNED = "Unassigned";
  }

  public enum Type {
    CHANGE_CYPHER_SPEC((byte) 0x14, Name.CHANGE_CYPHER_SPEC), ALERT((byte) 0x15, Name.ALERT), HANDSHAKE((byte) 0x16, Name.HANDSHAKE), APPLICATION_DATA((byte) 0x17, Name.APPLICATION_DATA),
    HEARTBEAT((byte) 0x18, Name.HEARTBEAT), TLS12_CID((byte) 0x19, Name.TLS12_CID), UNASSIGNED((byte) 0xFF, Name.UNASSIGNED);

    private byte data;
    private String name;

    private Type(byte data, String name) {
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

    public static Type of(int type) {
      return of((byte) type);
    }

    public static Type of(byte type) {
      for (Type t : values()) {
        if (t.getByte() == type) {
          return t;
        }
      }
      return UNASSIGNED;
    }

    @JsonCreator
    public static Type of(String type) {
      for (Type t : values()) {
        if (StringUtils.equals(t.getName(), type)) {
          return t;
        }
      }
      return UNASSIGNED;
    }

    public static boolean isValid(byte type) {
      return of(type) != null;
    }

    @Override
    public String toString() {
      return getName() + "(" + String.format("0x%02X", getByte()) + ")";
    }
  }

}
