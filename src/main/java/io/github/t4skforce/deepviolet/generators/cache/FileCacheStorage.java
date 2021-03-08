package io.github.t4skforce.deepviolet.generators.cache;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StreamCorruptedException;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.cache.HttpCacheEntry;
import org.apache.http.client.cache.HttpCacheUpdateCallback;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.ManagedHttpCacheStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileCacheStorage extends ManagedHttpCacheStorage {
  private static final Logger LOG = LoggerFactory.getLogger(FileCacheStorage.class);

  private File cacheDir;

  public FileCacheStorage(final CacheConfig config, File cacheDir) {
    super(config);
    this.cacheDir = cacheDir;
    this.cacheDir.mkdirs();
  }

  @Override
  public HttpCacheEntry getEntry(final String url) throws IOException {
    HttpCacheEntry entry = super.getEntry(url);
    if (entry == null) {
      entry = loadCacheEnrty(url);
    }
    return entry;
  }

  @Override
  public void putEntry(final String url, final HttpCacheEntry entry) throws IOException {
    super.putEntry(url, entry);
    saveCacheEntry(url, entry);
  }

  @Override
  public void removeEntry(final String url) throws IOException {
    super.removeEntry(url);
    File cache = getCacheFile(url);
    if (cache != null && cache.exists()) {
      cache.delete();
    }
  }

  @Override
  public void updateEntry(final String url, final HttpCacheUpdateCallback callback) throws IOException {
    super.updateEntry(url, callback);
    HttpCacheEntry entry = loadCacheEnrty(url);
    if (entry != null) {
      entry = callback.update(entry);
      saveCacheEntry(url, entry);
    }
  }

  private void saveCacheEntry(String url, HttpCacheEntry entry) {
    if (entry.getStatusCode() < HttpStatus.SC_MULTIPLE_CHOICES && entry.getStatusCode() >= HttpStatus.SC_OK) {
      ObjectOutputStream stream = null;
      try {
        File cache = getCacheFile(url);
        stream = new ObjectOutputStream(new FileOutputStream(cache));
        stream.writeObject(entry);
        stream.close();
      } catch (FileNotFoundException e) {
        LOG.error(e.getMessage(), e);
      } catch (IOException e) {
        LOG.error(e.getMessage(), e);
      }
    }
  }

  private HttpCacheEntry loadCacheEnrty(String url) throws IOException {
    HttpCacheEntry entry = null;
    File cache = getCacheFile(url);
    if (cache != null && cache.exists()) {
      synchronized (this) {
        ObjectInputStream stream = null;
        try {
          stream = new ObjectInputStream(new FileInputStream(cache));
          entry = (HttpCacheEntry) stream.readObject();
          stream.close();
        } catch (ClassNotFoundException e) {
          LOG.error(e.getMessage(), e);
        } catch (StreamCorruptedException e) {
          LOG.error(e.getMessage(), e);
        } catch (FileNotFoundException e) {
          LOG.error(e.getMessage(), e);
        } catch (IOException e) {
          LOG.error(e.getMessage(), e);
        }
      }
    }
    return entry;
  }

  private File getCacheFile(String url) {
    String cleanUrl = url;
    if (!StringUtils.startsWith(url, "http")) {
      cleanUrl = StringUtils.replace(url, RegExUtils.removeFirst(url, "http[s]?://.*$"), StringUtils.EMPTY);
    }
    return new File(cacheDir, DigestUtils.md5Hex(cleanUrl));
  }
}
