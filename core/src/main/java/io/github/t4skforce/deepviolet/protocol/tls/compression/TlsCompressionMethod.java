package io.github.t4skforce.deepviolet.protocol.tls.compression;

import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

// https://tools.ietf.org/html/rfc3749
// https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml
@Deprecated
public class TlsCompressionMethod {

  public static final TlsCompressionMethod NULL = new TlsCompressionMethod((byte) 0x00, "Null");
  public static final TlsCompressionMethod DEFLATE = new TlsCompressionMethod((byte) 0x01, "DEFLATE");
  public static final TlsCompressionMethod LZS = new TlsCompressionMethod((byte) 0x40, "LZS");

  private static final Map<Byte, TlsCompressionMethod> LOOKUP = new HashMap<Byte, TlsCompressionMethod>();

  static {
    LOOKUP.put(NULL.getByte(), NULL);
    LOOKUP.put(DEFLATE.getByte(), DEFLATE);
    LOOKUP.put(LZS.getByte(), LZS);
    for (int i = 2; i <= 63; i++) {
      LOOKUP.put(Byte.valueOf((byte) i), new TlsCompressionMethod((byte) i, "UNASSIGNED"));
    }
    for (int i = 65; i <= 223; i++) {
      LOOKUP.put(Byte.valueOf((byte) i), new TlsCompressionMethod((byte) i, "UNASSIGNED"));
    }
    for (int i = 224; i <= 255; i++) {
      LOOKUP.put(Byte.valueOf((byte) i), new TlsCompressionMethod((byte) i, "Reserved for Private Use"));
    }
  }

  private static final Set<TlsCompressionMethod> RESERVED_RANGE = new HashSet<TlsCompressionMethod>();

  private byte data;
  private String name;

  private TlsCompressionMethod(byte data, String name) {
    this.data = data;
    this.name = name;
  }

  public byte getByte() {
    return data;
  }

  public String getName() {
    return name;
  }

  public static TlsCompressionMethod of(byte data) throws TlsProtocolException {
    if (LOOKUP.containsKey(data)) {
      return LOOKUP.get(data);
    }
    throw new TlsProtocolException("Invalid CompressionMethod[" + TlsUtils.toString(data) + "]");
  }

  @Override
  public String toString() {
    return String.format("%s(0x%02X)", this.name, this.data);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + data;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    TlsCompressionMethod other = (TlsCompressionMethod) obj;
    if (data != other.data)
      return false;
    return true;
  }

}
