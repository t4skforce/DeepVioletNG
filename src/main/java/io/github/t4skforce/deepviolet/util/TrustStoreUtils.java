package io.github.t4skforce.deepviolet.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class TrustStoreUtils {

  public static KeyStore loadDefaultTrustStore() {
    Path location = null;
    String type = null;
    String password = null;

    String locationProperty = System.getProperty("javax.net.ssl.trustStore");
    if ((null != locationProperty) && (locationProperty.length() > 0)) {
      Path p = Paths.get(locationProperty);
      File f = p.toFile();
      if (f.exists() && f.isFile() && f.canRead()) {
        location = p;
      }
    } else {
      String javaHome = System.getProperty("java.home");
      location = Paths.get(javaHome, "lib", "security", "jssecacerts");
      if (!location.toFile().exists()) {
        location = Paths.get(javaHome, "lib", "security", "cacerts");
      }
    }

    String passwordProperty = System.getProperty("javax.net.ssl.trustStorePassword");
    if ((null != passwordProperty) && (passwordProperty.length() > 0)) {
      password = passwordProperty;
    } else {
      password = "changeit";
    }

    String typeProperty = System.getProperty("javax.net.ssl.trustStoreType");
    if ((null != typeProperty) && (typeProperty.length() > 0)) {
      type = passwordProperty;
    } else {
      type = KeyStore.getDefaultType();
    }

    KeyStore trustStore = null;
    try {
      trustStore = KeyStore.getInstance(type, Security.getProvider("SUN"));
    } catch (KeyStoreException e) {
      throw new RuntimeException(e);
    }

    try (InputStream is = Files.newInputStream(location)) {
      trustStore.load(is, password.toCharArray());
    } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    return trustStore;
  }

  /**
   * Creates the key managers required to initiate the {@link SSLContext}, using a JKS keystore as
   * an input.
   *
   * @param filepath - the path to the JKS keystore.
   * @param keystorePassword - the keystore's password.
   * @param keyPassword - the key's passsword.
   * @return {@link KeyManager} array that will be used to initiate the {@link SSLContext}.
   * @throws KeyStoreException
   * @throws IOException
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws UnrecoverableKeyException
   * @throws Exception
   */
  public static KeyManager[] createKeyManagers(InputStream file, String keystorePassword,
      String keyPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
      IOException, UnrecoverableKeyException {
    KeyStore keyStore = KeyStore.getInstance("JKS");
    try (InputStream keyStoreFile = new BufferedInputStream(file)) {
      keyStore.load(keyStoreFile, keystorePassword.toCharArray());
    }
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, keyPassword.toCharArray());
    return kmf.getKeyManagers();
  }

  /**
   * Creates the trust managers required to initiate the {@link SSLContext}, using a JKS keystore as
   * an input.
   *
   * @param filepath - the path to the JKS keystore.
   * @param keystorePassword - the keystore's password.
   * @return {@link TrustManager} array, that will be used to initiate the {@link SSLContext}.
   * @throws KeyStoreException
   * @throws IOException
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws Exception
   */
  public static TrustManager[] createTrustManagers(InputStream file, String keystorePassword)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    KeyStore trustStore;
    if (file == null) {
      trustStore = TrustStoreUtils.loadDefaultTrustStore();
    } else {
      trustStore = KeyStore.getInstance("JKS");
      try (InputStream keyStoreFile = new BufferedInputStream(file)) {
        trustStore.load(keyStoreFile, keystorePassword.toCharArray());
      }
    }
    TrustManagerFactory trustFactory = TrustManagerFactory
        .getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustFactory.init(trustStore);
    return trustFactory.getTrustManagers();
  }

}
