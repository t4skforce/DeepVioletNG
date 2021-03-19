package io.github.t4skforce;

import com.squareup.javapoet.JavaFile;

import io.github.t4skforce.deepviolet.generators.CodeGenerator;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Mojo(name = "code-generator", defaultPhase = LifecyclePhase.GENERATE_SOURCES)
public class CodeGeneratorMojo extends AbstractMojo {

  private static final Logger LOG = LoggerFactory.getLogger(CodeGeneratorMojo.class);

  @Parameter(defaultValue = "${project}", required = true, readonly = true)
  private MavenProject project;

  @Parameter(defaultValue = "${project.basedir}/src/main/java", required = true)
  private File src;

  private List<CodeGenerator> generators = new ArrayList<>();

  public void execute() throws MojoExecutionException, MojoFailureException {
    try {
      Reflections reflections = new Reflections(this.getClass().getPackageName());
      for (Class<? extends CodeGenerator> generator : reflections.getSubTypesOf(CodeGenerator.class)) {
        if (!Modifier.isAbstract(generator.getModifiers())) {
          generators.add(generator.getDeclaredConstructor().newInstance());
        }
      }
      for (CodeGenerator generator : generators) {
        build(Paths.get(src.toURI()), generator.getClass().getSimpleName(), generator.sources());
      }
    } catch (Exception e) {
      throw new MojoExecutionException(e.getMessage(), e);
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
          LOG.info("Could not write generated code for class {}", javaFile.typeSpec.name, e);
          throw e;
        } catch (Exception e) {
          LOG.info("Could not initialize generator {} for class {}", generator, javaFile.typeSpec.name, e);
        }
      }
    } else {
      LOG.info("No code generated from class {}", generator);
    }
  }

}
