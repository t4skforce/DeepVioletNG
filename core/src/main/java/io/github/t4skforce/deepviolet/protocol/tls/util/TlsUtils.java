package io.github.t4skforce.deepviolet.protocol.tls.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * 
 * Should be handled in TlsMapper
 */
@Deprecated
public abstract class TlsUtils {
  private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

  public static final byte[] enc16be(int val, byte[] buff) {
    return enc16be(val, buff, 0);
  }

  public static final byte[] enc16be(int val, byte[] buff, int off) {
    buff[off] = (byte) (val >>> 8);
    buff[off + 1] = (byte) val;
    return buff;
  }

  public static final byte[] enc24be(int val, byte[] buff) {
    return enc24be(val, buff, 0);
  }

  public static final byte[] enc24be(int val, byte[] buff, int off) {
    buff[off] = (byte) (val >>> 16);
    buff[off + 1] = (byte) (val >>> 8);
    buff[off + 2] = (byte) val;
    return buff;
  }

  public static final byte[] enc32be(int val, byte[] buff) {
    return enc32be(val, buff, 0);
  }

  public static final byte[] enc32be(int val, byte[] buff, int off) {
    buff[off] = (byte) (val >>> 24);
    buff[off + 1] = (byte) (val >>> 16);
    buff[off + 2] = (byte) (val >>> 8);
    buff[off + 3] = (byte) val;
    return buff;
  }

  public static final int dec16be(byte[] buff) {
    return dec16be(buff, 0);
  }

  public static final int dec16be(byte[] buff, int off) {
    return ((buff[off] & 0xFF) << 8) | (buff[off + 1] & 0xFF);
  }

  public static final int dec24be(byte[] buff, int off) {
    return ((buff[off] & 0xFF) << 16) | ((buff[off + 1] & 0xFF) << 8) | (buff[off + 2] & 0xFF);
  }

  public static final int dec32be(byte[] buff, int off) {
    return ((buff[off] & 0xFF) << 24) | ((buff[off + 1] & 0xFF) << 16) | ((buff[off + 2] & 0xFF) << 8) | (buff[off + 3] & 0xFF);
  }

  public static final String toString16(int[] buff) {
    return toString16(buff, ",");
  }

  public static final String toString16(int[] buff, String seperator) {
    List<String> retVal = new ArrayList<>();
    for (int b : buff) {
      retVal.add("[" + toString(enc16be(b, new byte[2])) + "]");
    }
    return StringUtils.join(retVal, seperator);
  }

  public static final String toString(byte b) {
    return String.format("0x%02X", b);
  }

  public static final String toString(byte[] buff) {
    return toString(buff, ",");
  }

  public static final String toString(byte[] buff, String seperator) {
    List<String> retVal = new ArrayList<String>();
    if (ArrayUtils.isNotEmpty(buff)) {
      for (byte b : buff) {
        retVal.add(String.format("0x%02X", b));
      }
    }
    return StringUtils.join(retVal, seperator);
  }
}
