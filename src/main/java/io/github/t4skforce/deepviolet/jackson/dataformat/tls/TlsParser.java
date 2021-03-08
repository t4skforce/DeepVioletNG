package io.github.t4skforce.deepviolet.jackson.dataformat.tls;

import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.FormatFeature;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonStreamContext;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.core.base.ParserMinimalBase;
import com.fasterxml.jackson.core.io.IOContext;
import com.fasterxml.jackson.core.json.DupDetector;
import com.fasterxml.jackson.core.sym.ByteQuadsCanonicalizer;
import com.fasterxml.jackson.core.util.TextBuffer;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsClientHello;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsHandshake;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsRecord;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.commons.lang3.StringUtils;

public class TlsParser extends ParserMinimalBase {

  /**
   * Enumeration that defines all togglable features for Tls generators.
   */
  public enum Feature implements FormatFeature {
    EMPTY_STRING_AS_NULL(false);

    protected final boolean defaultState;
    protected final int mask;

    /**
     * Method that calculates bit set (flags) of all features that are enabled by default.
     */
    public static int collectDefaults() {
      int flags = 0;
      for (Feature f : values()) {
        if (f.enabledByDefault()) {
          flags |= f.getMask();
        }
      }
      return flags;
    }

    private Feature(boolean defaultState) {
      this.defaultState = defaultState;
      this.mask = (1 << ordinal());
    }

    @Override
    public boolean enabledByDefault() {
      return defaultState;
    }

    @Override
    public int getMask() {
      return mask;
    }

    @Override
    public boolean enabledIn(int flags) {
      return (flags & mask) != 0;
    }
  }

  private IOContext ctx;
  private int generalParserFeatures;
  private int formatFeatures;
  private ObjectCodec codec;
  private ByteQuadsCanonicalizer can;
  private ByteBuffer bb;
  private TextBuffer textBuffer;
  private TlsReadContext streamReadContext;
  private int numberInt = -1;
  private TlsRecord.Type recordType;
  private TlsHandshake.Type handshakeType;
  private boolean emptyStringsToNull;

  public TlsParser(IOContext ctx, int generalParserFeatures, int formatFeatures, ObjectCodec codec, ByteQuadsCanonicalizer can, ByteBuffer bb) {
    super(generalParserFeatures);
    this.ctx = ctx;
    this.generalParserFeatures = generalParserFeatures;
    this.formatFeatures = formatFeatures;
    this.codec = codec;
    this.can = can;
    this.bb = bb;
    textBuffer = ctx.constructTextBuffer();
    DupDetector dups = JsonParser.Feature.STRICT_DUPLICATE_DETECTION.enabledIn(generalParserFeatures) ? DupDetector.rootDetector(this) : null;
    streamReadContext = TlsReadContext.createRootContext(dups);
    emptyStringsToNull = Feature.EMPTY_STRING_AS_NULL.enabledIn(generalParserFeatures);
    // start with object
    addToken(JsonToken.START_OBJECT);
  }

  @Override
  public ObjectCodec getCodec() {
    return codec;
  }

  @Override
  public void setCodec(ObjectCodec c) {
    codec = c;
  }

  private int cc = -1;

  @Override
  public JsonToken nextToken() throws IOException {

    if (streamReadContext.inObject()) {
      if (_currToken != JsonToken.FIELD_NAME) {
        // completed the whole Object?
        if (!streamReadContext.expectMoreValues()) {
          streamReadContext = streamReadContext.getParent();
          return (_currToken = JsonToken.END_OBJECT);
        }
        // return (_currToken = _decodePropertyName());
      }
    } else {
      if (!streamReadContext.expectMoreValues()) {
        streamReadContext = streamReadContext.getParent();
        return (_currToken = JsonToken.END_ARRAY);
      }
    }

    if (!tokenQueue.isEmpty()) {
      JsonToken retVal = deQueuedToken();
      return retVal;
    }

    int currentPos = this.bb.position();
    if (streamReadContext.inRoot()) {
      // RecordHeader
      if (currentPos == 0) {
        parseTlsRecordHeader();
      } else if (currentPos == TlsRecord.HEADER_LENGTH) {
        // Message data
        addField(TlsRecord.Fields.MESSAGE);
        addToken(JsonToken.START_OBJECT);
        switch (recordType) {
        case CHANGE_CYPHER_SPEC:
        case ALERT:
          throwParserException("Record(" + recordType.getName() + ") parsing not imeplemented");
          break;
        case HANDSHAKE:
          parseTlsHandshake();
          switch (handshakeType) {
          case HELLO_REQUEST:
            break;
          case CLIENT_HELLO:
            parseClientHello();
            break;
          case SERVER_HELLO:
          case CERTIFICATE:
          case SERVER_KEY_EXCHANGE:
          case CERTIFICATE_REQUEST:
          case SERVER_HELLO_DONE:
          case CERTIFICATE_VERIFY:
          case CLIENT_KEY_EXCHANGE:
          case FINISHED:
          default:
            throwParserException("Handshake(" + handshakeType.getName() + ") parsing not imeplemented");
            break;
          }
          break;
        case APPLICATION_DATA:
        case HEARTBEAT:
        case TLS12_CID:
        default:
          throwParserException("Record(" + recordType.getName() + ") parsing not imeplemented");
          break;
        }
        addToken(JsonToken.END_OBJECT);
      }
    }

    if (!tokenQueue.isEmpty()) {
      return deQueuedToken();
    }
    if (_currToken != JsonToken.END_OBJECT) {
      return (_currToken = JsonToken.END_OBJECT);
    }
    return (_currToken = JsonToken.NOT_AVAILABLE);
  }

  private void parseClientHello() {
    // Protocol Version
    addField(TlsClientHello.Fields.LEGACY_VERSION, getInt16());

    // Random
    addField(TlsClientHello.Fields.RANDOM, getBase64String(32));

    // SessionId
    addField(TlsClientHello.Fields.SESSIONID, getBase64String((int) this.bb.get()));
  }

  private String getBase64String(int byteCount) {
    byte[] data = new byte[byteCount];
    this.bb.get(data);
    return Base64.getEncoder().encodeToString(data);
  }

  private void parseTlsHandshake() {
    handshakeType = TlsHandshake.Type.of(getInt8());
    // Handshake Type
    final String typeName = StringUtils.defaultIfEmpty(handshakeType.getName(), TlsHandshake.Name.UNASSIGNED);
    addField(TlsHandshake.Fields.TYPE, typeName);

    // Length
    addField(TlsHandshake.Fields.LENGTH, getInt24());
  }

  private void parseTlsRecordHeader() {
    // Record Type
    recordType = TlsRecord.Type.of(getInt8());
    final String typeName = StringUtils.defaultIfEmpty(recordType.getName(), TlsRecord.Name.UNASSIGNED);
    addField(TlsRecord.Fields.TYPE, typeName);

    // Protocol Version
    addField(TlsRecord.Fields.PROTOCOL, getInt16());

    // Length
    addField(TlsRecord.Fields.LENGTH, getInt16());
  }

  @FunctionalInterface
  public interface Token {
    JsonToken apply() throws IOException;
  }

  private Queue<Token> tokenQueue = new ConcurrentLinkedQueue<>();

  private JsonToken deQueuedToken() throws IOException {
    return tokenQueue.poll().apply();
  }

  private void addToken(JsonToken t) {
    addToken(() -> {
      return (_currToken = t);
    });
  }

  private void addToken(Token t) {
    tokenQueue.add(t);
  }

  private void addField(String name) {
    addToken(() -> {
      streamReadContext.setCurrentName(name);
      return (_currToken = JsonToken.FIELD_NAME);
    });
  }

  private void addField(String name, String value) {
    addField(name);
    if (emptyStringsToNull && StringUtils.isEmpty(value)) {
      addToken(() -> {
        return (_currToken = JsonToken.VALUE_NULL);
      });
    } else {
      addToken(() -> {
        textBuffer.resetWithString(value);
        return (_currToken = JsonToken.VALUE_STRING);
      });
    }
  }

  private void addField(String name, Integer value) {
    addField(name);
    addToken(() -> {
      numberInt = value;
      return (_currToken = JsonToken.VALUE_NUMBER_INT);
    });
  }

  private void throwParserException(String msg) {
    addToken(() -> {
      throw new JsonParseException(this, msg);
    });
  }

  @Override
  public boolean nextFieldName(SerializableString str) throws IOException {
    return true;
  }

  @Override
  protected void _handleEOF() throws JsonParseException {
    // TODO Auto-generated method stub

  }

  @Override
  public String getCurrentName() throws IOException {
    if (_currToken == JsonToken.START_OBJECT || _currToken == JsonToken.START_ARRAY) {
      TlsReadContext parent = streamReadContext.getParent();
      return parent.getCurrentName();
    }
    return streamReadContext.getCurrentName();
  }

  @Override
  public void overrideCurrentName(String name) {
    // Simple, but need to look for START_OBJECT/ARRAY's "off-by-one" thing:
    TlsReadContext ctxt = streamReadContext;
    if (_currToken == JsonToken.START_OBJECT || _currToken == JsonToken.START_ARRAY) {
      ctxt = ctxt.getParent();
    }
    // Unfortunate, but since we did not expose exceptions, need to wrap
    try {
      ctxt.setCurrentName(name);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void close() throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public boolean isClosed() {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public JsonStreamContext getParsingContext() {
    return streamReadContext;
  }

  @Override
  public String getText() throws IOException {
    JsonToken t = _currToken;
    if (t == JsonToken.VALUE_STRING) {
      return textBuffer.contentsAsString();
    }
    if (t == null) { // null only before/after document
      return null;
    }
    if (t == JsonToken.FIELD_NAME) {
      return streamReadContext.getCurrentName();
    }
    if (t.isNumeric()) {
      return getNumberValue().toString();
    }
    return _currToken.asString();
  }

  @Override
  public char[] getTextCharacters() throws IOException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean hasTextCharacters() {
    if (_currToken == JsonToken.VALUE_STRING) {
      return textBuffer.hasTextAsCharacters();
    }
    return false;
  }

  @Override
  public int getTextLength() throws IOException {
    if (_currToken != null) { // null only before/after document
      if (_currToken == JsonToken.VALUE_STRING) {
        return textBuffer.size();
      }
      if (_currToken == JsonToken.FIELD_NAME) {
        return streamReadContext.getCurrentName().length();
      }
      if ((_currToken == JsonToken.VALUE_NUMBER_INT) || (_currToken == JsonToken.VALUE_NUMBER_FLOAT)) {
        return getNumberValue().toString().length();
      }
      return _currToken.asCharArray().length;
    }
    return 0;
  }

  @Override
  public int getTextOffset() throws IOException {
    return 0;
  }

  @Override
  public String getValueAsString() throws IOException {
    if (_currToken == JsonToken.VALUE_STRING) {
      return textBuffer.contentsAsString();
    }
    if (_currToken == null || _currToken == JsonToken.VALUE_NULL || !_currToken.isScalarValue()) {
      return null;
    }
    return getText();
  }

  @Override
  public String getValueAsString(String defaultValue) throws IOException {
    if (_currToken != JsonToken.VALUE_STRING) {
      if (_currToken == null || _currToken == JsonToken.VALUE_NULL || !_currToken.isScalarValue()) {
        return defaultValue;
      }
    }
    return getText();
  }

  @Override
  public int getText(Writer writer) throws IOException {
    JsonToken t = _currToken;
    if (t == JsonToken.VALUE_STRING) {
      return textBuffer.contentsToWriter(writer);
    }
    if (t == JsonToken.FIELD_NAME) {
      String n = streamReadContext.getCurrentName();
      writer.write(n);
      return n.length();
    }
    if (t != null) {
      if (t.isNumeric()) {
        return textBuffer.contentsToWriter(writer);
      }
      char[] ch = t.asCharArray();
      writer.write(ch);
      return ch.length;
    }
    return 0;
  }

  @Override
  public byte[] getBinaryValue(Base64Variant b64variant) throws IOException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Version version() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public JsonLocation getTokenLocation() {
    return new JsonLocation(ctx.getSourceReference(), 0, // bytes
        -1, -1, (int) 0);
  }

  @Override
  public JsonLocation getCurrentLocation() {
    return new JsonLocation(ctx.getSourceReference(), 0, // bytes
        -1, -1, (int) 0); // char offset, line, column
  }

  @Override
  public Number getNumberValue() throws IOException {
    if (_currToken == JsonToken.VALUE_NUMBER_INT) {
      return getIntValue();
    }
    return null;
  }

  @Override
  public NumberType getNumberType() throws IOException {
    if (_currToken == JsonToken.VALUE_NUMBER_INT) {
      return NumberType.INT;
    }
    return null;
  }

  @Override
  public int getIntValue() throws IOException {
    return numberInt;
  }

  @Override
  public long getLongValue() throws IOException {
    // TODO Auto-generated method stub
    return 0;
  }

  @Override
  public BigInteger getBigIntegerValue() throws IOException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public float getFloatValue() throws IOException {
    // TODO Auto-generated method stub
    return 0;
  }

  @Override
  public double getDoubleValue() throws IOException {
    // TODO Auto-generated method stub
    return 0;
  }

  @Override
  public BigDecimal getDecimalValue() throws IOException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public int releaseBuffered(OutputStream out) throws IOException {
    // TODO: do we need this?
    return super.releaseBuffered(out);
  }

  private int getInt8() {
    byte b = this.bb.get();
    return (b & 0xFF);
  }

  private int getInt16() {
    byte[] data = new byte[2];
    this.bb.get(data);
    return ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
  }

  private int getInt24() {
    byte[] data = new byte[3];
    this.bb.get(data);
    return ((data[0] & 0xFF) << 16) | ((data[1] & 0xFF) << 8) | (data[2] & 0xFF);
  }

}
