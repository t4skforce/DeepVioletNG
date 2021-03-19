package io.github.t4skforce.deepviolet.jackson.dataformat.tls;

import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.FormatFeature;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.base.GeneratorBase;
import com.fasterxml.jackson.core.io.IOContext;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;

public class TlsGenerator extends GeneratorBase {

  /**
   * Enumeration that defines all togglable features for CBOR generator.
   */
  public enum Feature implements FormatFeature {
    ;

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
    public boolean enabledIn(int flags) {
      return (flags & getMask()) != 0;
    }

    @Override
    public int getMask() {
      return mask;
    }
  }

  public TlsGenerator(IOContext ctxt, int stdFeatures, int formatFeatures, ObjectCodec codec, OutputStream out) {
    super(stdFeatures, codec, /* Write Context */ null);
  }

  /**
   * Alternative constructor that may be used to feed partially initialized content.
   * 
   * @param outputBuffer Buffer to use for output before flushing to the underlying stream
   * @param offset Offset pointing past already buffered content; that is, number of bytes of valid content to output, within buffer.
   */
  public TlsGenerator(IOContext ctxt, int stdFeatures, int formatFeatures, ObjectCodec codec, OutputStream out, byte[] outputBuffer, int offset, boolean bufferRecyclable) {
    super(stdFeatures, codec, /* Write Context */ null);
  }

  @Override
  public void flush() throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  protected void _releaseBuffers() {
    // TODO Auto-generated method stub

  }

  @Override
  protected void _verifyValueWrite(String typeMsg) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeStartArray() throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeEndArray() throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeStartObject() throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeEndObject() throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeFieldName(String name) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeString(String text) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeString(char[] buffer, int offset, int len) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeRawUTF8String(byte[] buffer, int offset, int len) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeUTF8String(byte[] buffer, int offset, int len) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeRaw(String text) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeRaw(String text, int offset, int len) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeRaw(char[] text, int offset, int len) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeRaw(char c) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeBinary(Base64Variant bv, byte[] data, int offset, int len) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNumber(int v) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNumber(long v) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNumber(BigInteger v) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNumber(double v) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNumber(float v) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNumber(BigDecimal v) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNumber(String encodedValue) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeBoolean(boolean state) throws IOException {
    // TODO Auto-generated method stub

  }

  @Override
  public void writeNull() throws IOException {
    // TODO Auto-generated method stub

  }

}
