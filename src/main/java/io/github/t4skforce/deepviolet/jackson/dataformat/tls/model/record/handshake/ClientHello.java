package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsClientHello;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.TlsVersion;

import java.util.List;

/*
 * https://tools.ietf.org/html/rfc5246 struct { ProtocolVersion client_version; Random random; SessionID session_id; CipherSuite cipher_suites<2..2^16-2>; CompressionMethod
 * compression_methods<1..2^8-1>; select (extensions_present) { case false: struct {}; case true: Extension extensions<0..2^16-1>; }; } ClientHello;
 */
@TlsClientHello
public class ClientHello extends HandshakeMessage {

  @JacksonXmlProperty(localName = TlsClientHello.Fields.LEGACY_VERSION, isAttribute = true)
  @JsonProperty(value = TlsClientHello.Fields.LEGACY_VERSION)
  private TlsVersion legacyVersion;

  @JsonProperty(value = TlsClientHello.Fields.RANDOM)
  private String random;

  @JsonProperty(value = TlsClientHello.Fields.SESSIONID)
  private String session;

  @JacksonXmlElementWrapper(localName = "ciphers")
  @JacksonXmlProperty(localName = "cipher")
  @JsonProperty(value = TlsClientHello.Fields.CIPHER_SUITES)
  private List<CipherSuite> ciphers;

  @JsonProperty(value = TlsClientHello.Fields.COMPRESSION_METHOD)
  private String compression;

  @JsonProperty(value = TlsClientHello.Fields.EXTENSIONS)
  private List<String> extensions;

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

  public List<CipherSuite> getCiphers() {
    return ciphers;
  }

  public void setCiphers(List<CipherSuite> ciphers) {
    this.ciphers = ciphers;
  }

  public String getCompression() {
    return compression;
  }

  public void setCompression(String compression) {
    this.compression = compression;
  }

  public List<String> getExtensions() {
    return extensions;
  }

  public void setExtensions(List<String> extensions) {
    this.extensions = extensions;
  }

}
