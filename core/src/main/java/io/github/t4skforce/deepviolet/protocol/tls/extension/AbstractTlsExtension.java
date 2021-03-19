package io.github.t4skforce.deepviolet.protocol.tls.extension;

import java.io.IOException;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

@Deprecated
public abstract class AbstractTlsExtension {

  public abstract TlsExtensionType getType();

  public String getName() {
    return Optional.ofNullable(getType()).map(TlsExtensionType::getName).orElse(StringUtils.EMPTY);
  }

  public boolean isRecommended() {
    return Optional.ofNullable(getType()).map(TlsExtensionType::isRecommended).orElse(Boolean.FALSE);
  }

  public boolean isReserved() {
    return Optional.ofNullable(getType()).map(TlsExtensionType::isReserved).orElse(Boolean.TRUE);
  }

  public boolean isUnassigned() {
    return Optional.ofNullable(getType()).map(TlsExtensionType::isUnassigned).orElse(Boolean.TRUE);
  }

  public boolean isReservedForPrivateUse() {
    return Optional.ofNullable(getType()).map(TlsExtensionType::isReservedForPrivateUse).orElse(Boolean.TRUE);
  }

  public boolean isValid() {
    return Optional.ofNullable(getType()).map(TlsExtensionType::isValid).orElse(Boolean.FALSE);
  }

  /**
   * return only bytes from the data section of the extension
   * 
   * @return
   */
  public abstract byte[] getData() throws IOException;

  /**
   * Return full byte representation of the tls extension
   * 
   * @return
   */
  public abstract byte[] getBytes() throws IOException;

  @Override
  public String toString() {
    return Optional.ofNullable(getType()).map(TlsExtensionType::toString).orElse(getName());
  }

}
