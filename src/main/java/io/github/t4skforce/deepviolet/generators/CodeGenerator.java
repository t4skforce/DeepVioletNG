package io.github.t4skforce.deepviolet.generators;

import com.squareup.javapoet.JavaFile;

import java.util.Date;
import java.util.Optional;

public interface CodeGenerator {

  public static final String FIELD_UPDATED = "UPDATED";

  public String getTargetSimpleName();

  public String getTargetPackageName();

  public String getTargetCanonicalName();

  public Date getTargetUpdated();

  public Date getSourceUpdated();

  public default boolean isChanged() {
    return getSourceUpdated().after(getTargetUpdated());
  }

  /**
   * Here you need to setup everyting to return {@see CodeGenerator#getSourceUpdated()}
   * 
   * @throws Exception
   */
  public void init() throws Exception;

  public Optional<JavaFile> build();

}
