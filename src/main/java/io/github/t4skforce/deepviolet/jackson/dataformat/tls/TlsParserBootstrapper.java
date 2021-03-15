package io.github.t4skforce.deepviolet.jackson.dataformat.tls;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.format.InputAccessor;
import com.fasterxml.jackson.core.format.MatchStrength;
import com.fasterxml.jackson.core.io.IOContext;
import com.fasterxml.jackson.core.sym.ByteQuadsCanonicalizer;

import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsRecord;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.TlsVersion;
import io.github.t4skforce.deepviolet.protocol.tls.TlsRecordTyp;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

import org.apache.commons.io.IOUtils;

public class TlsParserBootstrapper {

  protected final IOContext ctxt;
  protected final InputStream in;
  private byte[] inputBuffer;
  private int inputStart = 0;
  private int inputLen = 0;

  public TlsParserBootstrapper(IOContext ctxt, InputStream in) {
    this.ctxt = ctxt;
    this.in = in;
  }

  public TlsParserBootstrapper(IOContext ctxt, byte[] inputBuffer, int inputStart, int inputLen) {
    this.ctxt = ctxt;
    this.in = null;
    this.inputBuffer = inputBuffer;
    this.inputStart = inputStart;
    this.inputLen = inputLen;
  }

  public TlsParser constructParser(int factoryFeatures, int generalParserFeatures, int formatFeatures, ObjectCodec codec, ByteQuadsCanonicalizer rootByteSymbols)
      throws IOException, JsonParseException {
    ByteQuadsCanonicalizer can = rootByteSymbols.makeChild(factoryFeatures);

    ByteBuffer bb;
    if (in != null) {
      byte[] header = new byte[TlsRecord.HEADER_LENGTH];
      IOUtils.read(in, header);
      int size = ((header[TlsRecord.HEADER_LENGTH - 2] & 0xFF) << 8) | (header[TlsRecord.HEADER_LENGTH - 1] & 0xFF);
      bb = ByteBuffer.allocate(size + TlsRecord.HEADER_LENGTH).put(header).position(TlsRecord.HEADER_LENGTH);
      ReadableByteChannel channel = Channels.newChannel(in);
      IOUtils.readFully(channel, bb);
      bb.position(0);
    } else {
      bb = ByteBuffer.wrap(inputBuffer);
      bb.position(this.inputStart);
      bb.limit(this.inputStart + this.inputLen);
    }
    return new TlsParser(ctxt, generalParserFeatures, formatFeatures, codec, can, bb);
  }

  public static MatchStrength hasTlsFormat(InputAccessor acc) throws IOException {
    if (!acc.hasMoreBytes()) {
      return MatchStrength.INCONCLUSIVE;
    }
    byte[] bytes = new byte[5];
    for (int i = 0; i < 5; i++) {
      if (!acc.hasMoreBytes()) {
        return MatchStrength.NO_MATCH;
      }
      bytes[i] = acc.nextByte();
    }

    if (!TlsRecordTyp.isValid(bytes[0])) {
      return MatchStrength.NO_MATCH;
    }

    if (!TlsVersion.isValid(new byte[] { bytes[1], bytes[2] })) {
      return MatchStrength.NO_MATCH;
    }

    int length = TlsUtils.dec16be(new byte[] { bytes[3], bytes[4] });
    if (length <= 0 || length > TlsRecord.MAX_SIZE) {
      return MatchStrength.NO_MATCH;
    }

    return MatchStrength.SOLID_MATCH;
  }

}
