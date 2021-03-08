package io.github.t4skforce.deepviolet.jackson.dataformat.tls;

import com.fasterxml.jackson.core.TSFBuilder;

public class TlsFactoryBuilder extends TSFBuilder<TlsFactory, TlsFactoryBuilder> {

  /**
   * Set of {@link TlsParser.Feature}s enabled, as bitmask.
   */
  protected int formatParserFeatures;

  /**
   * Set of {@link TlsGenerator.Feature}s enabled, as bitmask.
   */
  protected int formatGeneratorFeatures;

  protected TlsFactoryBuilder() {
    formatParserFeatures = TlsFactory.DEFAULT_TLS_PARSER_FEATURE_FLAGS;
    formatGeneratorFeatures = TlsFactory.DEFAULT_TLS_GENERATOR_FEATURE_FLAGS;
  }

  public TlsFactoryBuilder(TlsFactory base) {
    super(base);
    formatParserFeatures = base._formatParserFeatures;
    formatGeneratorFeatures = base._formatGeneratorFeatures;
  }

  public TlsFactoryBuilder enable(TlsParser.Feature f) {
    formatParserFeatures |= f.getMask();
    return _this();
  }

  public TlsFactoryBuilder enable(TlsParser.Feature first, TlsParser.Feature... other) {
    formatParserFeatures |= first.getMask();
    for (TlsParser.Feature f : other) {
      formatParserFeatures |= f.getMask();
    }
    return _this();
  }

  public TlsFactoryBuilder disable(TlsParser.Feature f) {
    formatParserFeatures &= ~f.getMask();
    return _this();
  }

  public TlsFactoryBuilder disable(TlsParser.Feature first, TlsParser.Feature... other) {
    formatParserFeatures &= ~first.getMask();
    for (TlsParser.Feature f : other) {
      formatParserFeatures &= ~f.getMask();
    }
    return _this();
  }

  public TlsFactoryBuilder configure(TlsParser.Feature f, boolean state) {
    return state ? enable(f) : disable(f);
  }

  public TlsFactoryBuilder enable(TlsGenerator.Feature f) {
    formatGeneratorFeatures |= f.getMask();
    return _this();
  }

  public TlsFactoryBuilder enable(TlsGenerator.Feature first, TlsGenerator.Feature... other) {
    formatGeneratorFeatures |= first.getMask();
    for (TlsGenerator.Feature f : other) {
      formatGeneratorFeatures |= f.getMask();
    }
    return _this();
  }

  public TlsFactoryBuilder disable(TlsGenerator.Feature f) {
    formatGeneratorFeatures &= ~f.getMask();
    return _this();
  }

  public TlsFactoryBuilder disable(TlsGenerator.Feature first, TlsGenerator.Feature... other) {
    formatGeneratorFeatures &= ~first.getMask();
    for (TlsGenerator.Feature f : other) {
      formatGeneratorFeatures &= ~f.getMask();
    }
    return _this();
  }

  public TlsFactoryBuilder configure(TlsGenerator.Feature f, boolean state) {
    return state ? enable(f) : disable(f);
  }

  public int formatParserFeaturesMask() {
    return formatParserFeatures;
  }

  public int formatGeneratorFeaturesMask() {
    return formatGeneratorFeatures;
  }

  @Override
  public TlsFactory build() {
    return new TlsFactory(this);
  }

}
