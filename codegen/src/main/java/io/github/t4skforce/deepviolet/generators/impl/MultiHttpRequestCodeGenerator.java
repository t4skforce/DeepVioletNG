package io.github.t4skforce.deepviolet.generators.impl;

import com.google.common.net.HttpHeaders;
import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.TypeSpec;

import io.github.t4skforce.deepviolet.generators.JavaFileGenerator;
import io.github.t4skforce.deepviolet.generators.cache.FileCacheStorage;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.cache.CacheResponseStatus;
import org.apache.http.client.cache.HttpCacheContext;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClients;
import org.apache.http.impl.client.cache.ManagedHttpCacheStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class MultiHttpRequestCodeGenerator extends AbstractCodeGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(MultiHttpRequestCodeGenerator.class);

  private static final String JAVA_IO_TMPDIR = "java.io.tmpdir";

  protected static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36 Edg/88.0.705.63";

  private CloseableHttpClient client;

  private long cacheMaxSize = 51200L; // 50 MiB

  private int cacheMaxEntries = 300;

  private TimeUnit cacheMaxAgeUnit = TimeUnit.HOURS;

  private long cacheMaxAgeValue = 24;

  private SimpleDateFormat lastModifiedFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");

  protected JavaFileGenerator generator;

  protected TypeSpec.Builder typeSpec;

  protected TypeSpec.Builder testSpec;

  protected ClassName self;

  protected ClassName test;

  protected MultiHttpRequestCodeGenerator() throws Exception {
    super();
    CacheConfig cacheConfig = CacheConfig.custom().setMaxCacheEntries(cacheMaxEntries).setMaxObjectSize(cacheMaxSize).setHeuristicCachingEnabled(true)
        .setHeuristicDefaultLifetime(cacheMaxAgeUnit.toSeconds(cacheMaxAgeValue)).build(); // 50MB
    ManagedHttpCacheStorage storage = new FileCacheStorage(cacheConfig, new File(System.getProperty(JAVA_IO_TMPDIR), "http_cache"));
    RequestConfig requestConfig = RequestConfig.custom().build();
    List<Header> headers = new ArrayList<>();
    client = CachingHttpClients.custom().setCacheConfig(cacheConfig).setHttpCacheStorage(storage).setUserAgent(USER_AGENT).setDefaultHeaders(headers).setDefaultRequestConfig(requestConfig).build();
  }

  protected abstract String getClassName();

  @Override
  public void close() throws IOException {
    super.close();
    client.close();
  }

  /**
   * Runs before requests are sendt
   * 
   * @throws Exception
   */
  protected void before() throws Exception {
    // do nothing
  }

  protected void beforeTest() throws Exception {
    // do nothing
  }

  /**
   * Runs after all requests are being sendt
   * 
   * @throws Exception
   */
  protected void after() throws Exception {
    // do nothing
  }

  protected void afterTest() throws Exception {
    // do nothing
  }

  protected void setCacheMaxSize(long cacheMaxSize) {
    this.cacheMaxSize = cacheMaxSize;
  }

  protected void setCacheMaxEntries(int cacheMaxEntries) {
    this.cacheMaxEntries = cacheMaxEntries;
  }

  protected void setCacheMaxAgeUnit(TimeUnit cacheMaxAgeUnit) {
    this.cacheMaxAgeUnit = cacheMaxAgeUnit;
  }

  protected void setCacheMaxAgeValue(long cacheMaxAgeValue) {
    this.cacheMaxAgeValue = cacheMaxAgeValue;
  }

  protected List<JavaFileGenerator> getSources() throws Exception {
    generator = JavaFileGenerator.builder().classBuilder(getClassName()).build();
    self = ClassName.get(generator.getPackageName(), generator.getSimpleName());
    typeSpec = generator.spec();
    return Arrays.asList(generator);
  }

  @Override
  protected List<JavaFileGenerator> buildSources() throws Exception {
    List<JavaFileGenerator> retVal = getSources();
    if (CollectionUtils.isNotEmpty(retVal)) {
      before();
      Date maxDate = Collections.max(retVal.stream().map(g -> g.getTargetUpdated()).filter(Objects::nonNull).collect(Collectors.toList()));
      HttpCacheContext context = HttpCacheContext.create();
      List<ResponseProcessor> processors = getProcessors();
      maxDate = doProcess(maxDate, context, processors);
      Date lastUpdate = maxDate;
      retVal.forEach(g -> g.setSourceUpdated(lastUpdate));
      after();
      return retVal;
    }
    return Collections.emptyList();
  }

  private Date doProcess(Date maxDate, HttpCacheContext context, List<ResponseProcessor> processors) throws Exception, IOException, ClientProtocolException {
    for (ResponseProcessor processor : processors) {
      HttpRequestBase request = processor.getRequest();
      request.setHeader(HttpHeaders.IF_MODIFIED_SINCE, lastModifiedFormat.format(maxDate));
      LOG.info("{}: {}", HttpHeaders.IF_MODIFIED_SINCE, maxDate);
      try (CloseableHttpResponse response = client.execute(request, context)) {
        if (LOG.isDebugEnabled() || true) {
          CacheResponseStatus responseStatus = context.getCacheResponseStatus();
          switch (responseStatus) {
          case CACHE_HIT:
            LOG.info("A response was generated from the cache with no requests sent upstream");
            break;
          case CACHE_MODULE_RESPONSE:
            LOG.info("The response was generated directly by the caching module");
            break;
          case CACHE_MISS:
            LOG.info("The response came from an upstream server");
            break;
          case VALIDATED:
            LOG.info("The response was generated from the cache after validating the entry with the origin server");
            break;
          }
        }

        int statusCode = response.getStatusLine().getStatusCode();
        LOG.info("Requested URL({}):{}", statusCode, request.getURI().toString());
        if (statusCode == HttpStatus.SC_OK) {
          if (response.containsHeader(HttpHeaders.LAST_MODIFIED)) {
            try {
              Date responseUpdated = lastModifiedFormat.parse(response.getFirstHeader(HttpHeaders.LAST_MODIFIED).getValue());
              if (maxDate == null || responseUpdated.after(maxDate)) {
                maxDate = responseUpdated;
              }
            } catch (ParseException e) {
              // ignore
            }
          }
          processor.accept(response);
        } else if (statusCode > 399) {
          LOG.warn("HTTP status {}", statusCode);
        }
      }
    }
    return maxDate;
  }

  protected List<JavaFileGenerator> getTests() throws Exception {
    generator = JavaFileGenerator.builder().classBuilder(getClassName()).build();
    self = ClassName.get(generator.getPackageName(), generator.getSimpleName());
    typeSpec = generator.spec();
    generator = JavaFileGenerator.builder().classBuilder(StringUtils.join(getClassName(), "Test")).build();
    test = ClassName.get(generator.getPackageName(), generator.getSimpleName());
    testSpec = generator.spec();
    return Arrays.asList(generator);
  }

  @Override
  protected List<JavaFileGenerator> buildTests() throws Exception {
    List<JavaFileGenerator> retVal = getTests();
    if (CollectionUtils.isNotEmpty(retVal)) {
      beforeTest();
      Date maxDate = Collections.max(retVal.stream().map(g -> g.getTargetUpdated()).filter(Objects::nonNull).collect(Collectors.toList()));
      HttpCacheContext context = HttpCacheContext.create();
      List<ResponseProcessor> processors = getTestProcessors();
      maxDate = doProcess(maxDate, context, processors);
      Date lastUpdate = maxDate;
      retVal.forEach(g -> g.setSourceUpdated(lastUpdate));
      afterTest();
      return retVal;
    }
    return Collections.emptyList();
  }

  @FunctionalInterface
  protected interface HttpResponseProcessorFunction {
    void accept(CloseableHttpResponse httpResponse) throws Exception;
  }

  @FunctionalInterface
  protected interface EntityProcessorFunction extends HttpResponseProcessorFunction {
    @Override
    default void accept(CloseableHttpResponse httpResponse) throws Exception {
      accept(httpResponse.getEntity());
    }

    void accept(HttpEntity entity) throws Exception;
  }

  @FunctionalInterface
  protected interface StringProcessorFunction extends EntityProcessorFunction {
    @Override
    default void accept(HttpEntity entity) throws Exception {
      accept(IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8.name()));
    }

    void accept(String body) throws Exception;
  }

  protected abstract static class ResponseProcessor implements StringProcessorFunction {
    public abstract HttpRequestBase getRequest();

    public void accept(String body) throws Exception {
      // ignore
    }

    public static Builder builder() {
      return new Builder();
    }

    public static class Builder {
      private List<ResponseProcessor> processors = new ArrayList<>();

      private Builder() {

      }

      public Builder request(Supplier<HttpRequestBase> request, HttpResponseProcessorFunction... responseProcessors) {
        processors.add(new ResponseProcessor() {

          @Override
          public HttpRequestBase getRequest() {
            return request.get();
          }

          @Override
          public void accept(CloseableHttpResponse httpResponse) throws Exception {
            for (HttpResponseProcessorFunction responseProcessor : responseProcessors) {
              responseProcessor.accept(httpResponse);
            }
          }
        });
        return this;
      }

      public Builder request(Supplier<HttpRequestBase> request, EntityProcessorFunction... entityProcessors) {
        processors.add(new ResponseProcessor() {
          @Override
          public HttpRequestBase getRequest() {
            return request.get();
          }

          @Override
          public void accept(HttpEntity entity) throws Exception {
            for (EntityProcessorFunction entityProcessor : entityProcessors) {
              entityProcessor.accept(entity);
            }
          }
        });
        return this;
      }

      public Builder request(Supplier<HttpRequestBase> request, StringProcessorFunction... stringProcessors) {
        processors.add(new ResponseProcessor() {

          @Override
          public HttpRequestBase getRequest() {
            return request.get();
          }

          @Override
          public void accept(String body) throws Exception {
            for (StringProcessorFunction stringProcessor : stringProcessors) {
              stringProcessor.accept(body);
            }
          }
        });
        return this;
      }

      public Builder get(String url, HttpResponseProcessorFunction... processors) {
        return request(() -> {
          return new HttpGet(url);
        }, processors);
      }

      public Builder get(String url, EntityProcessorFunction... processors) {
        return request(() -> {
          return new HttpGet(url);
        }, processors);
      }

      public Builder get(String url, StringProcessorFunction... processors) {
        return request(() -> {
          return new HttpGet(url);
        }, processors);
      }

      public List<ResponseProcessor> build() {
        return processors;
      }
    }
  }

  protected abstract List<ResponseProcessor> getProcessors();

  protected List<ResponseProcessor> getTestProcessors() {
    return getProcessors();
  }

}
