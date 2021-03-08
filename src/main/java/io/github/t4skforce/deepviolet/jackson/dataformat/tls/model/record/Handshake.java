package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsRecord;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.AbstractRecord;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake.HandshakeMessage;

@JsonTypeName(TlsRecord.Name.HANDSHAKE)
public class Handshake extends AbstractRecord {

  @JsonProperty(value = TlsRecord.Fields.MESSAGE, required = true)
  private HandshakeMessage message;

  public Handshake() {
    super();
  }

  public HandshakeMessage getMessage() {
    return message;
  }

  public void setMessage(HandshakeMessage message) {
    this.message = message;
  }

}
