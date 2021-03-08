package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsClientHello;
import io.github.t4skforce.deepviolet.protocol.tls.TlsVersion;

/*
 * https://tools.ietf.org/html/rfc5246 struct { ProtocolVersion client_version; Random random; SessionID session_id; CipherSuite cipher_suites<2..2^16-2>; CompressionMethod
 * compression_methods<1..2^8-1>; select (extensions_present) { case false: struct {}; case true: Extension extensions<0..2^16-1>; }; } ClientHello;
 */
@TlsClientHello
public class ClientHello extends HandshakeMessage {

  @JsonProperty(value = TlsClientHello.Fields.LEGACY_VERSION)
  private TlsVersion legacyVersion;

  @JsonProperty(value = TlsClientHello.Fields.RANDOM)
  private String random;

  @JsonProperty(value = TlsClientHello.Fields.SESSIONID)
  private String session;

  public ClientHello() {
    super();
  }

  public TlsVersion getLegacyVersion() {
    return legacyVersion;
  }

  public void setLegacyVersion(TlsVersion legacyVersion) {
    this.legacyVersion = legacyVersion;
  }

  public String getRandom() {
    return random;
  }

  public void setRandom(String random) {
    this.random = random;
  }

  public String getSession() {
    return session;
  }

  public void setSession(String session) {
    this.session = session;
  }
}
