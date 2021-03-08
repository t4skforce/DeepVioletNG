package io.github.t4skforce.deepviolet.generators.mapper.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;

import org.apache.commons.lang3.BooleanUtils;

public class BooleanDeserializer extends StdDeserializer<Boolean> {

  protected BooleanDeserializer() {
    super((Class<?>) null);
  }

  protected BooleanDeserializer(Class<?> vc) {
    super(vc);
  }

  @Override
  public Boolean deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
    return BooleanUtils.toBooleanObject(p.getText());
  }

}
