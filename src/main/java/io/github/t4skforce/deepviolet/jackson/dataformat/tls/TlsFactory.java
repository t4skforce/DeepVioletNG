package io.github.t4skforce.deepviolet.jackson.dataformat.tls;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.format.InputAccessor;
import com.fasterxml.jackson.core.format.MatchStrength;
import com.fasterxml.jackson.core.io.IOContext;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.net.URL;

/**
 * Factory used for constructing {@link TlsParser} and {@link TlsParser} instances; both of which handle <a href="https://tools.ietf.org/html/rfc5246">Tls</a> encoded data.
 * <p>
 * Extends {@link JsonFactory} mostly so that users can actually use it in place of regular non-TLS factory instances.
 * <p>
 * Note on using non-byte-based sources/targets (char based, like {@link java.io.Reader} and {@link java.io.Writer}): these can not be used for Tls Records; attempt will throw exception.
 * 
 */
public class TlsFactory extends JsonFactory {
  private static final long serialVersionUID = 1;

  /**
   * Name used to identify TLS format. (and returned by {@link #getFormatName()}
   */
  public final static String FORMAT_NAME = "TLS";

  /**
   * Bitfield (set of flags) of all parser features that are enabled by default.
   */
  final static int DEFAULT_TLS_PARSER_FEATURE_FLAGS = TlsParser.Feature.collectDefaults();

  /**
   * Bitfield (set of flags) of all generator features that are enabled by default.
   */
  final static int DEFAULT_TLS_GENERATOR_FEATURE_FLAGS = TlsGenerator.Feature.collectDefaults();

  protected int _formatParserFeatures;
  protected int _formatGeneratorFeatures;

  /**
   * Default constructor used to create factory instances. Creation of a factory instance is a light-weight operation, but it is still a good idea to reuse limited number of factory instances (and
   * quite often just a single instance): factories are used as context for storing some reused processing objects (such as symbol tables parsers use) and this reuse only works within context of a
   * single factory instance.
   */
  public TlsFactory() {
    this((ObjectCodec) null);
  }

  public TlsFactory(ObjectCodec oc) {
    super(oc);
    _formatParserFeatures = DEFAULT_TLS_PARSER_FEATURE_FLAGS;
    _formatGeneratorFeatures = DEFAULT_TLS_GENERATOR_FEATURE_FLAGS;
  }

  /**
   * Note: REQUIRES at least 2.2.1 -- unfortunate intra-patch dep but seems preferable to just leaving bug be as is
   * 
   * @since 2.2.1
   */
  public TlsFactory(TlsFactory src, ObjectCodec oc) {
    super(src, oc);
    _formatParserFeatures = src._formatParserFeatures;
    _formatGeneratorFeatures = src._formatGeneratorFeatures;
  }

  /**
   * Constructors used by {@link TlsFactoryBuilder} for instantiation.
   *
   * @since 3.0
   */
  protected TlsFactory(TlsFactoryBuilder b) {
    super(b, false);
    _formatParserFeatures = b.formatParserFeaturesMask();
    _formatGeneratorFeatures = b.formatGeneratorFeaturesMask();
  }

  @Override
  public TlsFactoryBuilder rebuild() {
    return new TlsFactoryBuilder(this);
  }

  /**
   * Main factory method to use for constructing {@link TlsFactory} instances with different configuration.
   */
  public static TlsFactoryBuilder builder() {
    return new TlsFactoryBuilder();
  }

  @Override
  public TlsFactory copy() {
    _checkInvalidCopy(TlsFactory.class);
    // note: as with base class, must NOT copy mapper reference
    return new TlsFactory(this, null);
  }

  /**
   * Method that we need to override to actually make restoration go through constructors etc. Also: must be overridden by sub-classes as well.
   */
  @Override
  protected Object readResolve() {
    return new TlsFactory(this, _objectCodec);
  }

  @Override
  public String getFormatName() {
    return FORMAT_NAME;
  }

  @Override
  public boolean canUseCharArrays() {
    return false;
  }

  @Override
  public MatchStrength hasFormat(InputAccessor acc) throws IOException {
    return TlsParserBootstrapper.hasTlsFormat(acc);
  }

  @Override
  public boolean canHandleBinaryNatively() {
    return true;
  }

  @Override
  public Class<TlsParser.Feature> getFormatReadFeatureType() {
    return TlsParser.Feature.class;
  }

  @Override
  public Class<TlsGenerator.Feature> getFormatWriteFeatureType() {
    return TlsGenerator.Feature.class;
  }

  /**
   * Method for enabling or disabling specified parser feature (check {@link TlsParser.Feature} for list of features)
   */
  public final TlsFactory configure(TlsParser.Feature f, boolean state) {
    if (state) {
      enable(f);
    } else {
      disable(f);
    }
    return this;
  }

  /**
   * Method for enabling specified parser feature (check {@link TlsParser.Feature} for list of features)
   */
  public TlsFactory enable(TlsParser.Feature f) {
    _formatParserFeatures |= f.getMask();
    return this;
  }

  /**
   * Method for disabling specified parser features (check {@link TlsParser.Feature} for list of features)
   */
  public TlsFactory disable(TlsParser.Feature f) {
    _formatParserFeatures &= ~f.getMask();
    return this;
  }

  /**
   * Checked whether specified parser feature is enabled.
   */
  public final boolean isEnabled(TlsParser.Feature f) {
    return (_formatParserFeatures & f.getMask()) != 0;
  }

  @Override
  public int getFormatParserFeatures() {
    return _formatParserFeatures;
  }

  /**
   * Method for enabling or disabling specified generator feature (check {@link TlsGenerator.Feature} for list of features)
   */
  public final TlsFactory configure(TlsGenerator.Feature f, boolean state) {
    if (state) {
      enable(f);
    } else {
      disable(f);
    }
    return this;
  }

  /**
   * Method for enabling specified generator features (check {@link TlsGenerator.Feature} for list of features)
   */
  public TlsFactory enable(TlsGenerator.Feature f) {
    _formatGeneratorFeatures |= f.getMask();
    return this;
  }

  /**
   * Method for disabling specified generator feature (check {@link TlsGenerator.Feature} for list of features)
   */
  public TlsFactory disable(TlsGenerator.Feature f) {
    _formatGeneratorFeatures &= ~f.getMask();
    return this;
  }

  /**
   * Check whether specified generator feature is enabled.
   */
  public final boolean isEnabled(TlsGenerator.Feature f) {
    return (_formatGeneratorFeatures & f.getMask()) != 0;
  }

  @Override
  public int getFormatGeneratorFeatures() {
    return _formatGeneratorFeatures;
  }

  @SuppressWarnings("resource")
  @Override
  public TlsParser createParser(File f) throws IOException {
    IOContext ctxt = _createContext(f, true);
    return _createParser(_decorate(new FileInputStream(f), ctxt), ctxt);
  }

  @Override
  public TlsParser createParser(URL url) throws IOException {
    IOContext ctxt = _createContext(url, true);
    return _createParser(_decorate(_optimizedStreamFromURL(url), ctxt), ctxt);
  }

  @Override
  public TlsParser createParser(InputStream in) throws IOException {
    IOContext ctxt = _createContext(in, false);
    return _createParser(_decorate(in, ctxt), ctxt);
  }

  @Override
  public TlsParser createParser(byte[] data) throws IOException {
    return createParser(data, 0, data.length);
  }

  @SuppressWarnings("resource")
  @Override
  public TlsParser createParser(byte[] data, int offset, int len) throws IOException {
    IOContext ctxt = _createContext(data, true);
    if (_inputDecorator != null) {
      InputStream in = _inputDecorator.decorate(ctxt, data, 0, data.length);
      if (in != null) {
        return _createParser(in, ctxt);
      }
    }
    return _createParser(data, offset, len, ctxt);
  }

  /**
   * Method for constructing {@link JsonGenerator} for generating Tls-encoded output.
   * <p>
   * Since Tls format always uses UTF-8 internally, <code>enc</code> argument is ignored.
   */
  @Override
  public TlsGenerator createGenerator(OutputStream out, JsonEncoding enc) throws IOException {
    final IOContext ctxt = _createContext(out, false);
    return _createTlsGenerator(ctxt, _generatorFeatures, _formatGeneratorFeatures, _objectCodec, _decorate(out, ctxt));
  }

  /**
   * Method for constructing {@link JsonGenerator} for generating Tls-encoded output.
   * <p>
   * Since Tls format always uses UTF-8 internally, no encoding need to be passed to this method.
   */
  @Override
  public TlsGenerator createGenerator(OutputStream out) throws IOException {
    final IOContext ctxt = _createContext(out, false);
    return _createTlsGenerator(ctxt, _generatorFeatures, _formatGeneratorFeatures, _objectCodec, _decorate(out, ctxt));
  }

  @Override
  protected IOContext _createContext(Object srcRef, boolean resourceManaged) {
    return super._createContext(srcRef, resourceManaged);
  }

  /**
   * Overridable factory method that actually instantiates desired parser.
   */
  @Override
  protected TlsParser _createParser(InputStream in, IOContext ctxt) throws IOException {
    return new TlsParserBootstrapper(ctxt, in).constructParser(_factoryFeatures, _parserFeatures, _formatParserFeatures, _objectCodec, _byteSymbolCanonicalizer);
  }

  /**
   * Overridable factory method that actually instantiates desired parser.
   */
  @Override
  protected JsonParser _createParser(Reader r, IOContext ctxt) throws IOException {
    return _nonByteSource();
  }

  @Override
  protected JsonParser _createParser(char[] data, int offset, int len, IOContext ctxt, boolean recyclable) throws IOException {
    return _nonByteSource();
  }

  /**
   * Overridable factory method that actually instantiates desired parser.
   */
  @Override
  protected TlsParser _createParser(byte[] data, int offset, int len, IOContext ctxt) throws IOException {
    return new TlsParserBootstrapper(ctxt, data, offset, len).constructParser(_factoryFeatures, _parserFeatures, _formatParserFeatures, _objectCodec, _byteSymbolCanonicalizer);
  }

  @Override
  protected TlsGenerator _createGenerator(Writer out, IOContext ctxt) throws IOException {
    return _nonByteTarget();
  }

  @Override
  protected TlsGenerator _createUTF8Generator(OutputStream out, IOContext ctxt) throws IOException {
    return _createTlsGenerator(ctxt, _generatorFeatures, _formatGeneratorFeatures, _objectCodec, out);
  }

  @Override
  protected Writer _createWriter(OutputStream out, JsonEncoding enc, IOContext ctxt) throws IOException {
    return _nonByteTarget();
  }

  private final TlsGenerator _createTlsGenerator(IOContext ctxt, int stdFeat, int formatFeat, ObjectCodec codec, OutputStream out) throws IOException {
    TlsGenerator gen = new TlsGenerator(ctxt, stdFeat, formatFeat, _objectCodec, out);
    return gen;
  }

  protected <T> T _nonByteSource() {
    throw new UnsupportedOperationException("Can not create parser for non-byte-based source");
  }

  protected <T> T _nonByteTarget() {
    throw new UnsupportedOperationException("Can not create generator for non-byte-based target");
  }

}
