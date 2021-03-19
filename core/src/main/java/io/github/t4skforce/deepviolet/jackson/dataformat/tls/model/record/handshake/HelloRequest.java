package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake;

import com.fasterxml.jackson.annotation.JsonTypeName;

@JsonTypeName("HelloRequest")
public class HelloRequest extends HandshakeMessage {
  public HelloRequest() {
    super();
  }
}
