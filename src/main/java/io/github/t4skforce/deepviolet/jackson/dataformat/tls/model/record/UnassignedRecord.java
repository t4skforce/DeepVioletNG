package io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record;

import com.fasterxml.jackson.annotation.JsonTypeName;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsRecord;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.AbstractRecord;

@JsonTypeName(TlsRecord.Name.UNASSIGNED)
public class UnassignedRecord extends AbstractRecord {
  public UnassignedRecord() {
    super();
  }
}
