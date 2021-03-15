package io.github.t4skforce.deepviolet.generators;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.TypeSpec;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

public class JavaFileGenerator {

  private TypeSpec.Builder typeSpec;

  private String simpleName;

  private String packageName;

  private Date targetUpdated = new Date(0);

  private Date sourceUpdated = new Date(1);

  private boolean changed = false;

  private JavaFileGenerator(String packageName, String simpleName, TypeSpec.Builder typeSpec) {
    this.packageName = packageName;
    this.simpleName = simpleName;
    this.typeSpec = typeSpec;
    try {
      Class<?> clazz = Class.forName(this.getFullyQualifiedName());
      Field updatedField = clazz.getField(CodeGenerator.FIELD_UPDATED);
      this.setTargetUpdated((Date) updatedField.get(null));
    } catch (Exception e) {
      this.changed = true;
    }
  }

  public boolean isChanged() {
    return changed || sourceUpdated.after(targetUpdated);
  }

  public void setChanged(boolean changed) {
    this.changed = changed;
    if (!changed) {
      targetUpdated = sourceUpdated;
    }
  }

  public void setSourceUpdated(Date date) {
    sourceUpdated = date;
  }

  public Date getSourceUpdated() {
    return sourceUpdated;
  }

  public Date getTargetUpdated() {
    return targetUpdated;
  }

  public void setTargetUpdated(Date targetUpdated) {
    this.targetUpdated = targetUpdated;
  }

  public String getSimpleName() {
    return simpleName;
  }

  public String getPackageName() {
    return packageName;
  }

  public String getFullyQualifiedName() {
    return StringUtils.join(Arrays.asList(packageName, simpleName), '.');
  }

  public TypeSpec.Builder spec() {
    return typeSpec;
  }

  public ClassName self() {
    return ClassName.get(packageName, simpleName);
  }

  public JavaFile build() {
    return JavaFile.builder(packageName, typeSpec.build()).skipJavaLangImports(true).build();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private static Pattern NAME_EXTRACT = Pattern.compile("^((?<package>.*)[.])?(?<name>.*)$", Pattern.MULTILINE);
    private TypeSpec.Builder typeSpec;
    private String packageName;
    private String simpleName;

    public Builder packageName(String name) {
      packageName = name;
      return this;
    }

    public Builder classBuilder(String name) {
      extractPackageAndClassName(name);
      typeSpec = TypeSpec.classBuilder(simpleName);
      return this;
    }

    public Builder interfaceBuilder(String name) {
      extractPackageAndClassName(name);
      typeSpec = TypeSpec.interfaceBuilder(simpleName);
      return this;
    }

    public Builder enumBuilder(String name) {
      extractPackageAndClassName(name);
      typeSpec = TypeSpec.enumBuilder(simpleName);
      return this;
    }

    public Builder annotationBuilder(String name) {
      extractPackageAndClassName(name);
      typeSpec = TypeSpec.annotationBuilder(simpleName);
      return this;
    }

    private void extractPackageAndClassName(String name) {
      Matcher matcher = NAME_EXTRACT.matcher(name);
      if (matcher.find()) {
        packageName = StringUtils.defaultIfBlank(matcher.group("package"), packageName);
        simpleName = StringUtils.defaultIfBlank(matcher.group("name"), simpleName);
      } else {
        simpleName = name;
      }
    }

    public JavaFileGenerator build() throws Exception {
      if (StringUtils.isEmpty(packageName)) {
        throw new IllegalArgumentException("packageName is missing!");
      }
      if (typeSpec == null) {
        throw new IllegalArgumentException("typeSpec is missing!");
      }

      return new JavaFileGenerator(packageName, simpleName, typeSpec);
    }
  }

}
