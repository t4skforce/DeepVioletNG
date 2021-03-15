package io.github.t4skforce.deepviolet.generators;

import com.squareup.javapoet.JavaFile;

import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainCodeGenerator implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(MainCodeGenerator.class);

  private List<CodeGenerator> generators = new ArrayList<>();

  private Path path;

  public MainCodeGenerator(Path path) throws Exception {
    Reflections reflections = new Reflections(this.getClass().getPackageName());
    for (Class<? extends CodeGenerator> generator : reflections.getSubTypesOf(CodeGenerator.class)) {
      if (!Modifier.isAbstract(generator.getModifiers())) {
        generators.add(generator.getDeclaredConstructor().newInstance());
      }
    }
    this.path = path;
  }

  public void build() throws IOException {
    for (CodeGenerator generator : generators) {
      build(path, generator.getClass().getSimpleName(), generator.sources());
    }
  }

  public void test() throws IOException {
    for (CodeGenerator generator : generators) {
      build(path, generator.getClass().getSimpleName(), generator.tests());
    }
  }

  private void build(Path path, String generator, List<JavaFile> javaFiles) throws IOException {
    if (CollectionUtils.isNotEmpty(javaFiles)) {
      for (JavaFile javaFile : javaFiles) {
        try {
          Path target = javaFile.writeToPath(path);
          LOG.info("Generated code for class {}", javaFile.typeSpec.name);
          LOG.debug("Written file: {}", target.toString());
        } catch (IOException e) {
          LOG.error("Could not write generated code for class {}", javaFile.typeSpec.name, e);
          throw e;
        } catch (Exception e) {
          LOG.error("Could not initialize generator {} for class {}", generator, javaFile.typeSpec.name, e);
        }
      }
    } else {
      LOG.warn("No code generated from class {}", generator);
    }
  }

  @Override
  public void close() throws IOException {
    for (CodeGenerator generator : generators) {
      generator.close();
    }
  }

  public static void main(String[] args) throws Exception {
    Boolean isSource = BooleanUtils.toBooleanObject(args[0], "source", "test", "test");
    Path path = Paths.get(args[1]);
    if (Files.exists(path)) {
      try (MainCodeGenerator generator = new MainCodeGenerator(path)) {
        if (isSource) {
          generator.build();
        } else {
          generator.test();
        }
      }
    } else {
      throw new FileNotFoundException(path.toString());
    }
  }

}
