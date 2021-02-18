package io.github.t4skforce.deepviolet.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum CompatibilityEnum {
  @JsonProperty("modern")
  MORDERN, @JsonProperty("intermediate")
  INTERMEDIATE, @JsonProperty("old")
  OLD;
}
