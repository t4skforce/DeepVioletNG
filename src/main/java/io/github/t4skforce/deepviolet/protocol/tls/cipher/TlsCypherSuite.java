package io.github.t4skforce.deepviolet.protocol.tls.cipher;

import io.github.t4skforce.deepviolet.json.CipherMap;
import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.io.IOException;

public class TlsCypherSuite implements Comparable<TlsCypherSuite> {

  private byte c1;

  private byte c2;

  private String iana;

  private TlsCypherSuite(byte c1, byte c2) throws IOException {
    this.c1 = c1;
    this.c2 = c2;
    CipherMap map = CipherMap.getInstance();
    if (CipherMap.getInstance().containsKey(c1, c2)) {
      this.iana = map.get(c1, c2).getIana();
    } else {
      this.iana = String.format("%s(%s)", "UNKNOWN", TlsUtils.toString(getBytes()));
    }
  }

  public byte[] getBytes() {
    return new byte[] { this.c1, this.c2 };
  }

  public static TlsCypherSuite of(byte[] data) throws IOException, TlsProtocolException {
    if (data != null && data.length == 2) {
      return new TlsCypherSuite(data[0], data[1]);
    }
    throw new TlsProtocolException("Invalid CypherSuite(" + TlsUtils.toString(data) + ")");
  }

  @Override
  public String toString() {
    return this.iana;
  }

  @Override
  public int compareTo(TlsCypherSuite o) {
    return this.iana.compareTo(o.iana);
  }

}
