package io.github.t4skforce.deepviolet.protocol.tls;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

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

  private static final Pattern TLS_REGEX = Pattern.compile("^TLSv1.([0-9])$", Pattern.CASE_INSENSITIVE);

  // https://tools.ietf.org/html/draft-davidben-tls-grease-01#section-5
  private static final Set<Integer> GREASE = new HashSet<>();

  static {
    GREASE.addAll(Arrays.asList(2570, // {0x0A,0x0A}
        6682, // {0x1A,0x1A}
        10794, // {0x2A,0x2A}
        14906, // {0x3A,0x3A}
        19018, // {0x4A,0x4A}
        23130, // {0x5A,0x5A}
        27242, // {0x6A,0x6A}
        31354, // {0x7A,0x7A}
        35466, // {0x8A,0x8A}
        39578, // {0x9A,0x9A}
        43690, // {0xAA,0xAA}
        47802, // {0xBA,0xBA}
        51914, // {0xCA,0xCA}
        56026, // {0xDA,0xDA}
        60138, // {0xEA,0xEA}
        64250 // {0xFA,0xFA}
    ));
  }

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

  @JsonValue
  public String getName() {
    return name;
  }

  public boolean isUnknown() {
    return unknown;
  }

  public byte[] getBytes() {
    return new byte[] { (byte) (version >>> 8), version.byteValue() };
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
      if (StringUtils.startsWith(name, "GREASE:0x")) {
        return of(Integer.parseInt(StringUtils.substring(name, 9), 16));
      }
      if (StringUtils.startsWith(name, "UNDEFINED:0x")) {
        return of(Integer.parseInt(StringUtils.substring(name, 12), 16));
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
  @JsonCreator
  public static TlsVersion of(int version) {
    return VERSIONS.computeIfAbsent(version, k -> {
      int f = (k >>> 8);
      if (f == 0x03 && ((k & 0xFF) - 1) <= 9) {
        return new TlsVersion(version, "TLSv1." + ((k & 0xFF) - 1));
      }
      if (GREASE.contains(k)) {
        return new TlsVersion(version, String.format("GREASE:0x%04X", k), true);
      }
      return new TlsVersion(version, String.format("UNDEFINED:0x%04X", k), true);
    });
  }

  @JsonCreator
  public static TlsVersion of(byte[] data) {
    return of(toInt(data));
  }

  public static boolean isValid(byte[] data) {
    return !of(data).unknown;
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
    if (this.unknown) {
      return name;
    }
    return name + " (" + String.format("0x%04X", version) + ")";
  }

  private static int toInt(byte[] data) {
    return data.length == 2 ? ((data[0] & 0xFF) << 8) | (data[1] & 0xFF) : -1;
  }
}
