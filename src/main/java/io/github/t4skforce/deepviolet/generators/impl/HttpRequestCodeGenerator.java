package io.github.t4skforce.deepviolet.generators.impl;

import com.google.common.net.HttpHeaders;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;

import io.github.t4skforce.deepviolet.generators.cache.FileCacheStorage;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.lang.model.element.Modifier;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.cache.CacheResponseStatus;
import org.apache.http.client.cache.HttpCacheContext;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClients;
import org.apache.http.impl.client.cache.ManagedHttpCacheStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class HttpRequestCodeGenerator extends AbstractCodeGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(HttpRequestCodeGenerator.class);

  private static final String FIELD_ETAG = "ETAG";

  private static final String JAVA_IO_TMPDIR = "java.io.tmpdir";

  protected static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36 Edg/88.0.705.63";

  protected String targetEtag;

  protected String sourceEtag;

  protected Date sourceUpdated;

  private CloseableHttpClient client;

  private CloseableHttpResponse response;

  private long cacheMaxSize = 51200L; // 50 MiB

  private int cacheMaxEntries = 300;

  private TimeUnit cacheMaxAgeUnit = TimeUnit.HOURS;

  private long cacheMaxAgeValue = 24;

  protected HttpRequestCodeGenerator() throws Exception {
    super();
  }

  @Override
  public void init() throws Exception {
    CacheConfig cacheConfig = CacheConfig.custom().setMaxCacheEntries(cacheMaxEntries).setMaxObjectSize(cacheMaxSize).setHeuristicCachingEnabled(true)
        .setHeuristicDefaultLifetime(cacheMaxAgeUnit.toSeconds(cacheMaxAgeValue)).build(); // 50MB
    ManagedHttpCacheStorage storage = new FileCacheStorage(cacheConfig, new File(System.getProperty(JAVA_IO_TMPDIR), "http_cache"));

    client = CachingHttpClients.custom().setCacheConfig(cacheConfig).setHttpCacheStorage(storage).build();

    SimpleDateFormat lastModifiedFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");
    HttpRequestBase request = getRequest();
    request.addHeader(HttpHeaders.USER_AGENT, USER_AGENT);
    request.addHeader(HttpHeaders.IF_MODIFIED_SINCE, lastModifiedFormat.format(getTargetUpdated()));
    try {
      // TODO: as per lifecycle there should not be compiled classes yet only in local dev. move to properties file?
      targetEtag = (String) targetClass.getDeclaredField(FIELD_ETAG).get(null);
    } catch (Exception e) {
      // ignore
    }
    if (StringUtils.isNotEmpty(targetEtag)) {
      request.addHeader(HttpHeaders.ETAG, targetEtag);
    }

    HttpCacheContext context = HttpCacheContext.create();
    try {
      response = client.execute(request, context);

      if (LOG.isDebugEnabled()) {
        CacheResponseStatus responseStatus = context.getCacheResponseStatus();
        switch (responseStatus) {
        case CACHE_HIT:
          LOG.debug("A response was generated from the cache with no requests sent upstream");
          break;
        case CACHE_MODULE_RESPONSE:
          LOG.debug("The response was generated directly by the caching module");
          break;
        case CACHE_MISS:
          LOG.debug("The response came from an upstream server");
          break;
        case VALIDATED:
          LOG.debug("The response was generated from the cache after validating the entry with the origin server");
          break;
        }
      }

      int statusCode = response.getStatusLine().getStatusCode();
      LOG.info("Requested URL({}):{}", statusCode, request.getURI().toString());
      if (statusCode == HttpStatus.SC_OK) {
        if (response.containsHeader(HttpHeaders.ETAG)) {
          sourceEtag = response.getFirstHeader(HttpHeaders.ETAG).getValue();
        }
        if (response.containsHeader(HttpHeaders.LAST_MODIFIED)) {
          try {
            sourceUpdated = lastModifiedFormat.parse(response.getFirstHeader(HttpHeaders.LAST_MODIFIED).getValue());
          } catch (ParseException e) {
            // ignore
          }
        }
      } else if (statusCode > 399) {
        LOG.warn("HTTP status {}", statusCode);
      }
    } catch (IOException e) {
      LOG.error(e.getMessage(), e);
    }
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

  /**
   * Defaults to returning Last-Modified value or target change date + 1ms when ETag is changed
   */
  @Override
  public Date getSourceUpdated() {
    // we have a source change date
    if (Objects.nonNull(sourceUpdated)) {
      return sourceUpdated;
    }
    // e-tag change
    if (StringUtils.isNotEmpty(sourceEtag) && StringUtils.equals(targetEtag, sourceEtag)) {
      return new Date(getTargetUpdated().getTime() + 1);
    }
    // no changes
    return getTargetUpdated();
  }

  @Override
  protected void doBuild() throws Exception {
    if (StringUtils.isNotEmpty(targetEtag)) {
      typeSpec.addField(FieldSpec.builder(String.class, FIELD_ETAG, Modifier.PUBLIC, Modifier.STATIC, Modifier.FINAL).initializer(CodeBlock.of("$S", targetEtag)).build());
    }
    try {
      doBuild(response);
    } finally {
      try {
        response.close();
        client.close();
      } catch (IOException e) {
        // ignore
      }
    }
  }

  protected abstract HttpRequestBase getRequest();

  protected abstract void doBuild(CloseableHttpResponse response) throws Exception;

}
