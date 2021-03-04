package io.github.t4skforce.deepviolet.generators;

import com.squareup.javapoet.JavaFile;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainCodeGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(MainCodeGenerator.class);

  private List<CodeGenerator> generators = new ArrayList<>();

  private Path srcPath;

  public MainCodeGenerator(Path srcPath) throws Exception {
    Reflections reflections = new Reflections(this.getClass().getPackageName());
    for (Class<? extends CodeGenerator> generator : reflections.getSubTypesOf(CodeGenerator.class)) {
      if (!Modifier.isAbstract(generator.getModifiers())) {
        generators.add(generator.getDeclaredConstructor().newInstance());
      }
    }
    this.srcPath = srcPath;
  }

  public void build() throws IOException {
    for (CodeGenerator generator : generators) {
      try {
        generator.init();
        if (generator.isChanged()) {
          Optional<JavaFile> jf = generator.build();
          if (jf.isPresent()) {
            Path target = jf.get().writeToPath(srcPath);
            LOG.info("Generated code for class {}", generator.getTargetSimpleName());
          } else {
            LOG.warn("Not generate code for class {}", generator.getTargetSimpleName());
          }
        } else {
          LOG.info("Skipped {}", generator.getTargetSimpleName());
        }
      } catch (IOException e) {
        LOG.error("Could not write generated code for class {}", generator.getTargetSimpleName());
        throw e;
      } catch (Exception e) {
        LOG.error("Could not initialize generator {} for class {}", generator.getClass().getSimpleName(), generator.getTargetSimpleName());
      }
    }
  }

  public static void main(String[] args) throws Exception {
    Path path = Paths.get(args[0]);
    if (Files.exists(path)) {
      new MainCodeGenerator(path).build();
    } else {
      throw new FileNotFoundException(path.toString());
    }
  }

}
