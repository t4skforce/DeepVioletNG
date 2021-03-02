package io.github.t4skforce.deepviolet.protocol.tls.message;

import io.github.t4skforce.deepviolet.json.TlsVersion;
import io.github.t4skforce.deepviolet.protocol.tls.cipher.TlsCypherSuite;
import io.github.t4skforce.deepviolet.protocol.tls.compression.TlsCompressionMethod;
import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.extension.AbstractTlsExtension;
import io.github.t4skforce.deepviolet.protocol.tls.extension.GenericTlsExtension;
import io.github.t4skforce.deepviolet.protocol.tls.extension.SupportedVersionsTlsExtension;
import io.github.t4skforce.deepviolet.protocol.tls.extension.TlsExtensionType;
import io.github.t4skforce.deepviolet.protocol.tls.handshake.TlsHandshakeType;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TlsClientHello extends TlsMessage {

  private static final Logger LOG = LoggerFactory.getLogger(TlsClientHello.class);

  private static final TlsHandshakeType TYPE = TlsHandshakeType.CLIENT_HELLO;

  private int length;

  private TlsVersion legacy_version;

  private byte[] random;

  private byte[] sessionId;

  private List<TlsCypherSuite> ciphers;

  private List<TlsCompressionMethod> compression;

  private List<AbstractTlsExtension> extensions;

  public TlsClientHello(int length, TlsVersion legacy_version, byte[] random, byte[] sessionId,
      List<TlsCypherSuite> ciphers, List<TlsCompressionMethod> compressionMethods,
      List<AbstractTlsExtension> extensions) {
    this.length = length;
    this.legacy_version = legacy_version;
    this.random = random;
    this.sessionId = sessionId;
    this.ciphers = ciphers;
    this.compression = compressionMethods;
    this.extensions = extensions;
  }

  @Override
  public byte[] getBytes() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public TlsHandshakeType getType() {
    return TYPE;
  }

  @Override
  public int getLength() {
    return length;
  }

  @Override
  public boolean isValid() {
    return false;
  }

  @Override
  public String toString() {
    return "TlsClientHello [length=" + length + ", legacy_version=" + legacy_version + ", ciphers="
        + ciphers + ", compression=" + compression + ", extensions=" + extensions + "]";
  }

  public static TlsClientHello of(byte[] data) throws IOException, TlsProtocolException {
    TlsHandshakeType type = TlsHandshakeType.of(data);
    if (TYPE.equals(type)) {
      try {
        int length = TlsUtils.dec24be(data, 1);

        final TlsVersion legacy_version = TlsVersion.of(TlsUtils.dec16be(data, 4));

        ByteBuffer bb = ByteBuffer.wrap(data);
        bb.position(6);
        byte[] random = new byte[32];
        bb.get(random);

        byte[] sessionId = getSessionId(bb);

        List<TlsCypherSuite> ciphers = getCipers(bb);

        List<TlsCompressionMethod> compressionMethods = getCompression(bb);
        List<AbstractTlsExtension> extensions = getExtensions(data, length, bb);

        return new TlsClientHello(length, legacy_version, random, sessionId, ciphers,
            compressionMethods, extensions);
      } catch (IndexOutOfBoundsException e) {
        throw new TlsProtocolException("Invalid ClientHello", e);
      }
    }
    throw new TlsProtocolException("Invalid HandshakeType " + type);
  }

  private static byte[] getSessionId(ByteBuffer bb) {
    int sessionIdLength = (int) bb.get();
    byte[] sessionId = new byte[sessionIdLength];
    bb.get(sessionId);
    return sessionId;
  }

  private static List<TlsCypherSuite> getCipers(ByteBuffer bb)
      throws IOException, TlsProtocolException {
    byte[] lcb = new byte[2];
    bb.get(lcb);
    int lenCipers = TlsUtils.dec16be(lcb);

    byte[] cbytes = new byte[lenCipers];
    bb.get(cbytes);

    List<TlsCypherSuite> ciphers = new ArrayList<>();
    for (int i = 0; i < lenCipers; i += 2) {
      ciphers.add(TlsCypherSuite.of(new byte[] { cbytes[i], cbytes[i + 1] }));
    }
    return ciphers;
  }

  private static List<TlsCompressionMethod> getCompression(ByteBuffer bb)
      throws TlsProtocolException {
    List<TlsCompressionMethod> compressionMethods = new ArrayList<>();
    int compressionMethodLength = (int) bb.get();
    for (int i = 0; i < compressionMethodLength; i++) {
      compressionMethods.add(TlsCompressionMethod.of(bb.get()));
    }
    return compressionMethods;
  }

  private static List<AbstractTlsExtension> getExtensions(byte[] data, int length, ByteBuffer bb)
      throws TlsProtocolException {
    List<AbstractTlsExtension> extensions = new ArrayList<>();
    // extensions_present
    if (bb.position() < length) {
      int extensionLength = TlsUtils.dec16be(data, bb.position());
      bb.position(bb.position() + 2);
      byte[] extensionBytes = new byte[extensionLength];
      bb.get(extensionBytes, 0, extensionBytes.length);

      ByteBuffer ebb = ByteBuffer.wrap(extensionBytes);
      while (ebb.position() < extensionLength) {
        byte[] typeb = new byte[2];
        ebb.get(typeb);
        TlsExtensionType etype = TlsExtensionType.of(typeb);
        byte[] lenb = new byte[2];
        ebb.get(lenb);
        int extLength = TlsUtils.dec16be(lenb);
        byte[] edata = new byte[extLength];
        ebb.get(edata);
        if (TlsExtensionType.SUPPORTED_VERSIONS.equals(etype)) {
          extensions.add(SupportedVersionsTlsExtension.of(edata, TYPE));
        } else {
          extensions.add(GenericTlsExtension.of(etype, edata));
        }
      }
    }
    return extensions;
  }

}
