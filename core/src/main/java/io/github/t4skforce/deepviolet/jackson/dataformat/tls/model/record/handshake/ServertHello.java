package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake;

import com.fasterxml.jackson.annotation.JsonTypeName;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsHandshake;

/*
 * https://tools.ietf.org/html/rfc5246 struct { ProtocolVersion server_version; Random random; SessionID session_id; CipherSuite cipher_suite; CompressionMethod compression_method; select
 * (extensions_present) { case false: struct {}; case true: Extension extensions<0..2^16-1>; }; } ServerHello;
 */
@JsonTypeName(TlsHandshake.Name.SERVER_HELLO)
public class ServertHello extends HandshakeMessage {
  public ServertHello() {
    super();
  }
}