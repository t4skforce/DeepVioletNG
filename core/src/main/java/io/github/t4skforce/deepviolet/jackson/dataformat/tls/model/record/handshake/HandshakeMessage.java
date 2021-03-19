package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsHandshake;

@TlsHandshake
@JsonSubTypes({ @Type(value = ClientHello.class, name = TlsHandshake.Name.CLIENT_HELLO), @Type(value = ServertHello.class, name = TlsHandshake.Name.SERVER_HELLO) })
public abstract class HandshakeMessage {

  @JacksonXmlProperty(localName = TlsHandshake.Fields.LENGTH, isAttribute = true)
  @JsonProperty(value = TlsHandshake.Fields.LENGTH, required = true)
  private int length;

  public HandshakeMessage() {
    super();
  }

  public int getLength() {
    return length;
  }

  public void setLength(int length) {
    this.length = length;
  }
}
