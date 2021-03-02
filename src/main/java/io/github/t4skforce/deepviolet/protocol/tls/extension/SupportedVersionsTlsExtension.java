package io.github.t4skforce.deepviolet.protocol.tls.extension;

import io.github.t4skforce.deepviolet.json.TlsVersion;
import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.handshake.TlsHandshakeType;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class SupportedVersionsTlsExtension extends AbstractTlsExtension {

  private static final String TO_STRING_FORMAT = "%s(%s)";

  private static final TlsExtensionType TYPE = TlsExtensionType.SUPPORTED_VERSIONS;

  private TlsVersion selectedVersion = null;

  private List<TlsVersion> versions = new ArrayList<>();

  public SupportedVersionsTlsExtension(List<TlsVersion> versions) {
    this.versions = versions;
  }

  public SupportedVersionsTlsExtension(TlsVersion selectedVersion) {
    super();
  }

  @Override
  public TlsExtensionType getType() {
    return TYPE;
  }

  @Override
  public byte[] getData() throws IOException {
    return null;
  }

  @Override
  public byte[] getBytes() throws IOException {
    return null;
  }

  public TlsVersion getSelectedVersion() {
    return this.selectedVersion;
  }

  public void setSelectedVersion(TlsVersion selectedVersion) {
    versions.clear();
    this.selectedVersion = selectedVersion;
  }

  public List<TlsVersion> getVersions() {
    return versions;
  }

  public void setVersions(List<TlsVersion> versions) {
    this.versions = versions;
    this.selectedVersion = null;
  }

  // https://tools.ietf.org/html/rfc8446#section-4.2.1
  public static SupportedVersionsTlsExtension of(byte[] data, TlsHandshakeType handshake)
      throws TlsProtocolException {
    ByteBuffer bb = ByteBuffer.wrap(data);
    switch (handshake) {
    case CLIENT_HELLO:
      List<TlsVersion> versions = new ArrayList<>();
      int ilen = bb.get();
      for (int i = 0; i <= ilen / 2; i += 2) {
        byte[] bvers = new byte[2];
        bb.get(bvers);
        versions.add(TlsVersion.of(TlsUtils.dec16be(bvers)));
      }
      return new SupportedVersionsTlsExtension(versions);
    case SERVER_HELLO:
    case HELLO_RETRY_REQUEST:
      byte[] bvers = new byte[2];
      bb.get(bvers);
      return new SupportedVersionsTlsExtension(TlsVersion.of(TlsUtils.dec16be(bvers)));
    default:
      throw new TlsProtocolException(
          "Invalid HandshakeType[" + handshake + "] for SupportedVersions");
    }
  }

  @Override
  public String toString() {
    if (selectedVersion != null) {
      return String.format(TO_STRING_FORMAT, TYPE.getName(), selectedVersion);
    } else {
      return String.format(TO_STRING_FORMAT, TYPE.getName(), versions);
    }
  }

}
