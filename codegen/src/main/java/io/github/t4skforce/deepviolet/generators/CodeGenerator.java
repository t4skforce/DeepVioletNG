package io.github.t4skforce.deepviolet.generators;

import com.squareup.javapoet.JavaFile;

import java.io.Closeable;
import java.util.List;

public interface CodeGenerator extends Closeable {

  public static final String FIELD_UPDATED = "UPDATED";

  public List<JavaFile> sources() throws Exception;

  public List<JavaFile> tests() throws Exception;

}
