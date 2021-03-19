package io.github.t4skforce.deepviolet.protocol.tls.extension;

import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.io.IOException;

import org.apache.commons.io.output.ByteArrayOutputStream;

@Deprecated
public class GenericTlsExtension extends AbstractTlsExtension {

  private TlsExtensionType type;
  private byte[] data;

  public GenericTlsExtension(TlsExtensionType type, byte[] data) {
    this.type = type;
    this.data = data;
  }

  @Override
  public TlsExtensionType getType() {
    return this.type;
  }

  @Override
  public byte[] getData() throws IOException {
    return this.data;
  }

  @Override
  public byte[] getBytes() throws IOException {
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      out.write(type.getBytes());
      out.write(TlsUtils.enc16be(this.data.length, new byte[2]));
      out.write(this.data);
      return out.toByteArray();
    }
  }

  public static GenericTlsExtension of(TlsExtensionType type, byte[] data) {
    return new GenericTlsExtension(type, data);
  }

}
