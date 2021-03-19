package io.github.t4skforce.deepviolet.jackson.dataformat.tls.databind;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.MapperBuilder;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.TlsFactory;

/**
 * Specialized {@link ObjectMapper} to use with TLS format backend.
 *
 */
public class TlsMapper extends ObjectMapper {
  private static final long serialVersionUID = 1L;

  /**
   * Base implementation for "Vanilla" {@link ObjectMapper}, used with TLS backend.
   *
   */
  public static class Builder extends MapperBuilder<TlsMapper, Builder> {
    public Builder(TlsMapper m) {
      super(m);
    }
  }

  public TlsMapper() {
    this(new TlsFactory());
  }

  public TlsMapper(TlsFactory f) {
    super(f);
  }

  protected TlsMapper(TlsMapper src) {
    super(src);
  }

  @SuppressWarnings("unchecked")
  public static TlsMapper.Builder builder() {
    return new Builder(new TlsMapper());
  }

  public static Builder builder(TlsFactory streamFactory) {
    return new Builder(new TlsMapper(streamFactory));
  }

  @Override
  public TlsMapper copy() {
    _checkInvalidCopy(TlsMapper.class);
    return new TlsMapper(this);
  }

  @Override
  public TlsFactory getFactory() {
    return (TlsFactory) _jsonFactory;
  }

}
