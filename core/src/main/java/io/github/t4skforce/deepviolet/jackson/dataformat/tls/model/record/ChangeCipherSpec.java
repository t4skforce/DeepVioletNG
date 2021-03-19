package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsRecord;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.AbstractRecord;

@JsonTypeName(TlsRecord.Name.CHANGE_CYPHER_SPEC)
public class ChangeCipherSpec extends AbstractRecord {

  @JsonProperty(value = TlsRecord.Fields.MESSAGE, required = true)
  private int payload;

  public ChangeCipherSpec() {
    super();
  }

}
