package io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations;

import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonValue;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.apache.commons.lang3.StringUtils;

/**
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
 *
 */

@Documented
@Target({ ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@JacksonAnnotationsInside
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonPropertyOrder(value = { "type", "length" })
public @interface TlsHandshake {

  public abstract class Fields {
    public static final String TYPE = "type";
    public static final String LENGTH = "length";
  }

  public abstract class Name {
    public static final String HELLO_REQUEST = "HelloRequest";
    public static final String CLIENT_HELLO = "ClientHello";
    public static final String SERVER_HELLO = "ServerHello";
    public static final String HELLO_VERIFY_REQUEST = "HelloVerifyRequest";
    public static final String NEW_SESSION_TICKET = "NewSessionTicket";
    public static final String END_OF_EARLY_DATA = "EndOfEarlyData";
    public static final String HELLO_RETRY_REQUEST = "HelloRetryRequest";
    public static final String ENCRYPTED_EXTENSIONS = "EncryptedExtensions";
    public static final String CERTIFICATE = "Certificate";
    public static final String SERVER_KEY_EXCHANGE = "ServerKeyExchange";
    public static final String CERTIFICATE_REQUEST = "CertificateRequest";
    public static final String SERVER_HELLO_DONE = "ServerHelloDone";
    public static final String CERTIFICATE_VERIFY = "CertificateVerify";
    public static final String CLIENT_KEY_EXCHANGE = "ClientKeyExchange";
    public static final String FINISHED = "Finished";
    public static final String CERTIFICATE_URL = "CertificateURL";
    public static final String CERTIFICATE_STATUS = "CertificateStatus";
    public static final String SUPPLEMENTAL_DATA = "SupplimentalData";
    public static final String KEY_UPDATE = "KeyUpdate";
    public static final String COMPRESSED_CERTIFICATE = "CompressedCertificate";
    public static final String ENCRYPTED_KEY_TRANSPORT_KEY = "EncryptedKeyTransportKey";
    public static final String MESSAGE_HASH = "MessageHash";
    public static final String UNASSIGNED = "Unassigned";
  }

  public enum Type {
    HELLO_REQUEST((byte) 0x00, Name.HELLO_REQUEST), CLIENT_HELLO((byte) 0x01, Name.CLIENT_HELLO), SERVER_HELLO((byte) 0x02, Name.SERVER_HELLO),
    HELLO_VERIFY_REQUEST((byte) 0x03, Name.HELLO_VERIFY_REQUEST), NEW_SESSION_TICKET((byte) 0x04, Name.NEW_SESSION_TICKET), END_OF_EARLY_DATA((byte) 0x05, Name.END_OF_EARLY_DATA),
    HELLO_RETRY_REQUEST((byte) 0x06, Name.HELLO_RETRY_REQUEST), ENCRYPTED_EXTENSIONS((byte) 0x08, Name.ENCRYPTED_EXTENSIONS), CERTIFICATE((byte) 0x0B, Name.CERTIFICATE),
    SERVER_KEY_EXCHANGE((byte) 0x0C, Name.SERVER_KEY_EXCHANGE), CERTIFICATE_REQUEST((byte) 0x0D, Name.CERTIFICATE_REQUEST), SERVER_HELLO_DONE((byte) 0x0E, Name.SERVER_HELLO_DONE),
    CERTIFICATE_VERIFY((byte) 0x0F, Name.CERTIFICATE_VERIFY), CLIENT_KEY_EXCHANGE((byte) 0x10, Name.CLIENT_KEY_EXCHANGE), FINISHED((byte) 0x14, Name.FINISHED),
    CERTIFICATE_URL((byte) 0x15, Name.CERTIFICATE_URL), CERTIFICATE_STATUS((byte) 0x16, Name.CERTIFICATE_STATUS), SUPPLEMENTAL_DATA((byte) 0x17, Name.SUPPLEMENTAL_DATA),
    KEY_UPDATE((byte) 0x18, Name.KEY_UPDATE), COMPRESSED_CERTIFICATE((byte) 0x19, Name.COMPRESSED_CERTIFICATE), ENCRYPTED_KEY_TRANSPORT_KEY((byte) 0x1A, Name.ENCRYPTED_KEY_TRANSPORT_KEY),
    MESSAGE_HASH((byte) 0xFE, Name.MESSAGE_HASH);

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

    public static Type of(Integer type) {
      return of(type.byteValue());
    }

    public static Type of(byte type) {
      for (Type t : values()) {
        if (t.getByte() == type) {
          return t;
        }
      }
      return null;
    }

    @JsonCreator
    public static Type of(String type) {
      for (Type t : values()) {
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

}
