package io.github.t4skforce.deepviolet.generators.impl;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.TypeSpec;

import io.github.t4skforce.deepviolet.generators.CodeGenerator;

import java.util.Date;
import java.util.Optional;

import javax.lang.model.element.Modifier;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractCodeGenerator implements CodeGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(AbstractCodeGenerator.class);

  protected Class<?> targetClass;

  protected TypeSpec.Builder typeSpec;

  protected Date targetUpdated = new Date(0);

  protected ClassName self;

  protected AbstractCodeGenerator() throws Exception {
    typeSpec = TypeSpec.classBuilder(getTargetSimpleName()).addModifiers(Modifier.PUBLIC).addJavadoc("This is a auto generated class by {@link $T}\n", this.getClass());
    try {
      // TODO: as per lifecycle there should not be compiled classes yet only in local dev. move to properties file?
      targetClass = Class.forName(getTargetCanonicalName());
      try {
        targetUpdated = (Date) targetClass.getDeclaredField(FIELD_UPDATED).get(null);
      } catch (Exception e) {
        // ignore
      }
    } catch (ClassNotFoundException e) {
      // ignore
    }
    self = ClassName.get(getTargetPackageName(), getTargetSimpleName());
  }

  @Override
  public Date getTargetUpdated() {
    return targetUpdated;
  }

  @Override
  public String getTargetSimpleName() {
    if (targetClass != null) {
      return targetClass.getSimpleName();
    }
    return StringUtils.substring(getTargetCanonicalName(), StringUtils.lastIndexOf(getTargetCanonicalName(), ".") + 1);
  }

  @Override
  public String getTargetPackageName() {
    if (targetClass != null) {
      return targetClass.getPackageName();
    }
    return StringUtils.substring(getTargetCanonicalName(), 0, StringUtils.lastIndexOf(getTargetCanonicalName(), "."));
  }

  protected abstract void doBuild() throws Exception;

  @Override
  public Optional<JavaFile> build() {
    try {
      typeSpec.addField(
          FieldSpec.builder(Date.class, FIELD_UPDATED, Modifier.PUBLIC, Modifier.STATIC, Modifier.FINAL).initializer(CodeBlock.of("new $T($LL)", Date.class, getSourceUpdated().getTime())).build());
      doBuild();
      return Optional.of(JavaFile.builder(getTargetPackageName(), typeSpec.build()).skipJavaLangImports(true).build());
    } catch (Exception e) {
      LOG.error(e.getMessage(), e);
      return Optional.empty();
    }
  }

}
