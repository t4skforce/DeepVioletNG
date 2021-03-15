package io.github.t4skforce.deepviolet.protocol.tls.extension;

import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.ArrayUtils;

/**
 * This is a auto generated class by {@link io.github.t4skforce.deepviolet.generators.impl.TlsExtensionTypeCodeGenerator}
 * <br/>based on <a href="https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv">www.iana.org</a> specification
 */
public class TlsExtensionTypeGenerated {
  public static final Date UPDATED = new Date(1614390074000L);

  private static final String RESERVED_FOR_PRIVATE_USE = "reserved_for_private_use";

  private static final String UNASSIGNED = "unassigned";

  private static final String RESERVED = "reserved";

  private static final Map<Integer, TlsExtensionTypeGenerated> LOOKUP = new HashMap<>();

  static {
  }

  private int value;

  private String name;

  private boolean recommended;

  private TlsExtensionTypeGenerated() {
    super();
  }

  private TlsExtensionTypeGenerated(int value, String name, boolean recommended) {
    this.value = value;
    this.name = name;
    this.recommended = recommended;
  }

  public int getValue() {
    return value;
  }

  public byte[] getBytes() {
    return TlsUtils.enc16be(value, new byte[2]);
  }

  public String getName() {
    return name;
  }

  public boolean isRecommended() {
    return recommended;
  }

  public boolean isReserved() {
    return RESERVED.equals(name);
  }

  public boolean isUnassigned() {
    return UNASSIGNED.equals(name);
  }

  public boolean isReservedForPrivateUse() {
    return RESERVED_FOR_PRIVATE_USE.equals(this.name);
  }

  public boolean isValid() {
    return !isReserved() && !isUnassigned() && !isReservedForPrivateUse();
  }

  /**
   * Returns instance of {@link TlsExtensionTypeGenerated} for given protocol bytes
   * @param buff
   * @return
   * @throws TlsProtocolException
   */
  public static TlsExtensionTypeGenerated of(byte[] buff) throws TlsProtocolException {
    if (ArrayUtils.isNotEmpty(buff) && buff.length == 2) {
      int key = TlsUtils.dec16be(buff);
      if (LOOKUP.containsKey(key)) {
        return LOOKUP.get(key);
      }
    }
    throw new TlsProtocolException("Given data [" + TlsUtils.toString(buff) + "] is invalid for ExtensionType");
  }

  @Override
  public String toString() {
    return name;
  }

  @Override
  public int hashCode() {
    return value;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    return value != ((TlsExtensionTypeGenerated) obj).value;
  }
}
