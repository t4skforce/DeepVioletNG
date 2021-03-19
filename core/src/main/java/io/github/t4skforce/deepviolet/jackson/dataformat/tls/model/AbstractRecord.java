package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsRecord;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.ChangeCipherSpec;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.Handshake;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.UnassignedRecord;

@TlsRecord
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = TlsRecord.Fields.TYPE, defaultImpl = UnassignedRecord.class)
@JsonSubTypes({ @Type(value = Handshake.class, name = TlsRecord.Name.HANDSHAKE), @Type(value = ChangeCipherSpec.class, name = TlsRecord.Name.CHANGE_CYPHER_SPEC) })
public abstract class AbstractRecord {

  @JacksonXmlProperty(localName = TlsRecord.Fields.PROTOCOL, isAttribute = true)
  @JsonProperty(value = TlsRecord.Fields.PROTOCOL, required = true)
  private TlsVersion protocol;

  @JacksonXmlProperty(localName = TlsRecord.Fields.LENGTH, isAttribute = true)
  @JsonProperty(value = TlsRecord.Fields.LENGTH, required = true)
  private int length;

  public AbstractRecord() {
    super();
  }

  public TlsVersion getProtocol() {
    return protocol;
  }

  public void setProtocol(TlsVersion protocol) {
    this.protocol = protocol;
  }

  public int getLength() {
    return length;
  }

  public void setLength(int length) {
    this.length = length;
  }
}
