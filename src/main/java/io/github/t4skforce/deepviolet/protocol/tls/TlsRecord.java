package io.github.t4skforce.deepviolet.protocol.tls;

import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.handshake.TlsHandshakeType;
import io.github.t4skforce.deepviolet.protocol.tls.message.TlsClientHello;
import io.github.t4skforce.deepviolet.protocol.tls.message.TlsServerHello;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.commons.lang3.NotImplementedException;

/**
 * https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html https://tools.ietf.org/html/rfc5246#page-37
 *
 */
@Deprecated
public class TlsRecord {

  public static final int MAX_RECORD_LEN = 16384;
  private TlsRecordTyp type;

  private TlsVersion version;

  private byte[] data;

  private TlsHandshakeType handhakeType = null;

  public TlsRecord(TlsRecordTyp type, TlsVersion version, int length, byte[] data) {
    this.type = type;
    this.version = version;
    this.data = data;
    if (isHandshake()) {
      this.handhakeType = TlsHandshakeType.of(this.data);
    }
  }

  public byte[] getBytes() throws IOException {
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      out.write(type.getByte());
      out.write(version.getBytes());
      out.write(TlsUtils.enc16be(this.data.length, new byte[2]));
      out.write(this.data);
      return out.toByteArray();
    }
  }

  public boolean isValid() {
    return getType() != null && getVersion() != null && getLength() < MAX_RECORD_LEN;
  }

  public byte[] getData() {
    return this.data;
  }

  public TlsRecordTyp getType() {
    return type;
  }

  public void setType(TlsRecordTyp type) {
    this.type = type;
  }

  public TlsVersion getVersion() {
    return version;
  }

  public void setVersion(TlsVersion version) {
    this.version = version;
  }

  public int getLength() {
    return this.data.length;
  }

  public void setData(byte[] data) {
    this.data = data;
  }

  public boolean isHandshake() {
    return TlsRecordTyp.HANDSHAKE.equals(type);
  }

  public TlsHandshakeType getHandhakeType() {
    return this.handhakeType;
  }

  public static TlsRecord of(InputStream in) throws TlsProtocolException, IOException {
    byte[] buff = new byte[5];
    in.read(buff, 0, 5);

    TlsRecordTyp type = TlsRecordTyp.of(buff[0]);
    TlsVersion version = TlsVersion.of(buff);
    int length = TlsUtils.dec16be(buff, 3);

    byte[] data = new byte[length];
    in.read(data, 0, length);

    if (type != null && version != null && length < MAX_RECORD_LEN) {
      return new TlsRecord(type, version, length, data);
    }
    throw new TlsProtocolException("Invalid TLS Record detected! request:[%s]".formatted(TlsUtils.toString(buff)));
  }

  public static TlsRecord of(TlsServerHello hello) {
    throw new NotImplementedException();
  }

  public static TlsRecord of(TlsClientHello hello) {
    throw new NotImplementedException();
  }

  @Override
  public String toString() {
    return "TlsRecord [type=" + getType() + ", version=" + getVersion() + ", length=" + getLength() + "]";
  }

}
