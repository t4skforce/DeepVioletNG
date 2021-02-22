package io.github.t4skforce.deepviolet.json;

import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TlsVersion {
  private static final String TL_SV1 = "TLSv1";
  private static final String SS_LV3 = "SSLv3";
  private static final String SS_LV2 = "SSLv2";
  public static final int UNKNOWN = 0xFFFF;
  public static final int SSL_V2 = 0x0200;
  public static final int SSL_V3 = 0x0300;
  public static final int TLS_V1 = 0x0301;
  public static final int TLS_V1_1 = 0x0302;
  public static final int TLS_V1_2 = 0x0303;
  public static final int TLS_V1_3 = 0x0304;

  private static final Pattern TLS_REGEX = Pattern.compile("^TLSv1.([0-9])$",
      Pattern.CASE_INSENSITIVE);

  private static final Map<Integer, TlsVersion> VERSIONS = new HashMap<>();

  static {
    VERSIONS.put(UNKNOWN, of(UNKNOWN));
    VERSIONS.put(SSL_V2, of(SSL_V2));
    VERSIONS.put(SSL_V3, of(SSL_V3));
    VERSIONS.put(TLS_V1, of(TLS_V1));
    VERSIONS.put(TLS_V1_1, of(TLS_V1_1));
    VERSIONS.put(TLS_V1_2, of(TLS_V1_2));
    VERSIONS.put(TLS_V1_3, of(TLS_V1_3));
  }

  private Integer version;
  private String name;

  private TlsVersion(int version, String name) {
    this.version = version;
    this.name = name;
  }

  /**
   * Get TlsVersion enum by it's string representation eg. TLSv1
   * 
   * @param name String representation of version
   * @return
   */
  @JsonCreator
  public static TlsVersion of(String name) {
    if (name != null) {
      if (name.equalsIgnoreCase(SS_LV2)) {
        return of(SSL_V2);
      } else if (name.equalsIgnoreCase(SS_LV3)) {
        return of(SSL_V3);
      } else if (name.equalsIgnoreCase(TL_SV1)) {
        return of(TLS_V1);
      }
      Matcher tlsm = TLS_REGEX.matcher(name);
      if (tlsm.matches()) {
        try {
          return of(0x0301 + Integer.parseInt(tlsm.group(1)));
        } catch (NumberFormatException e) {
          // should not be possible based on regex
        }
      }
    }
    return new TlsVersion(UNKNOWN, "UNKNOWN_NAME:" + name);
  }

  /**
   * Get TlsVersion enum by it's string representation eg. TLSv1
   * 
   * @param version Integer representation of version
   * @return
   */
  public static TlsVersion of(int version) {
    TlsVersion tv;
    if (VERSIONS.containsKey(version)) {
      return VERSIONS.get(version);
    }
    if (version == SSL_V2) {
      tv = new TlsVersion(version, SS_LV2);
    } else if (version == SSL_V3) {
      tv = new TlsVersion(version, SS_LV3);
    } else if (version >>> 8 == 0x03) {
      tv = new TlsVersion(version, "TLSv1." + ((version & 0xFF) - 1));
    } else {
      tv = new TlsVersion(version, String.format("UNKNOWN_VERSION:0x%04X", version));
    }
    VERSIONS.put(version, tv);
    return tv;
  }

  public Integer getVersion() {
    return version;
  }

  public String getName() {
    return name;
  }

  @Override
  public int hashCode() {
    return Objects.hash(version);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof TlsVersion)) {
      return false;
    }
    TlsVersion other = (TlsVersion) obj;
    return Objects.equals(version, other.version);
  }

  @Override
  public String toString() {
    return name + " (" + String.format("0x%04X", version) + ")";
  }
}
