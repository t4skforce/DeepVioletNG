package io.github.t4skforce.deepviolet.json;

import com.fasterxml.jackson.annotation.JsonCreator;

import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TlsVersion {
  private static final String STR_TLSV1 = "TLSv1";
  private static final String STR_SSLV3 = "SSLv3";
  private static final String STR_SSLV2 = "SSLv2";
  private static final String STR_TLSV1_1 = "TLSv1.1";
  private static final String STR_TLSV1_2 = "TLSv1.2";
  private static final String STR_TLSV1_3 = "TLSv1.3";

  public static final TlsVersion UNKNOWN = new TlsVersion(0xFFFF, "UNKNOWN_VERSION:0xFFFF", true);
  public static final TlsVersion SSL_V2 = new TlsVersion(0x0200, STR_SSLV2);
  public static final TlsVersion SSL_V3 = new TlsVersion(0x0300, STR_SSLV3);
  public static final TlsVersion TLS_V1 = new TlsVersion(0x0301, STR_TLSV1);
  public static final TlsVersion TLS_V1_1 = new TlsVersion(0x0302, STR_TLSV1_1);
  public static final TlsVersion TLS_V1_2 = new TlsVersion(0x0303, STR_TLSV1_2);
  public static final TlsVersion TLS_V1_3 = new TlsVersion(0x0304, STR_TLSV1_3);

  private static final Pattern TLS_REGEX = Pattern.compile("^TLSv1.([0-9])$",
      Pattern.CASE_INSENSITIVE);

  private static final Map<Integer, TlsVersion> VERSIONS = new HashMap<>();

  static {
    VERSIONS.put(UNKNOWN.getVersion(), UNKNOWN);
    VERSIONS.put(SSL_V2.getVersion(), SSL_V2);
    VERSIONS.put(SSL_V3.getVersion(), SSL_V3);
    VERSIONS.put(TLS_V1.getVersion(), TLS_V1);
    VERSIONS.put(TLS_V1_1.getVersion(), TLS_V1_1);
    VERSIONS.put(TLS_V1_2.getVersion(), TLS_V1_2);
    VERSIONS.put(TLS_V1_3.getVersion(), TLS_V1_3);
  }

  private Integer version;
  private String name;
  private boolean unknown;

  private TlsVersion(int version, String name) {
    this(version, name, false);
  }

  private TlsVersion(int version, String name, boolean unknown) {
    this.version = version;
    this.name = name;
    this.unknown = unknown;
  }

  public Integer getVersion() {
    return version;
  }

  public String getName() {
    return name;
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
      if (name.equalsIgnoreCase(STR_SSLV2)) {
        return SSL_V2;
      } else if (name.equalsIgnoreCase(STR_SSLV3)) {
        return SSL_V3;
      } else if (name.equalsIgnoreCase(STR_TLSV1)) {
        return TLS_V1;
      }
      Matcher tlsm = TLS_REGEX.matcher(name);
      if (tlsm.matches()) {
        return of(0x0301 + Integer.parseInt(tlsm.group(1), 10));
      }
    }
    return UNKNOWN;
  }

  /**
   * Get TlsVersion enum by it's string representation eg. TLSv1
   * 
   * @param version Integer representation of version
   * @return
   */
  public static TlsVersion of(int version) {
    return VERSIONS.computeIfAbsent(version, k -> {
      if (k >>> 8 == 0x03) {
        return new TlsVersion(version, "TLSv1." + ((k & 0xFF) - 1));
      }
      return new TlsVersion(version, String.format("UNKNOWN_VERSION:0x%04X", k), true);
    });
  }

  public byte[] getBytes() {
    return TlsUtils.enc16be(version, new byte[2]);
  }

  public static TlsVersion of(byte[] data) {
    return of(((data[1] & 0xFF) << 8) | (data[2] & 0xFF));
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
