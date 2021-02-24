package io.github.t4skforce.deepviolet.util;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import org.apache.commons.lang3.StringUtils;

public abstract class Downloader {

  private static final String HTTP_AGENT = "http.agent";
  private static final String USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36";

  
  public static String get(String requestUrl) throws IOException {
    String sysUa = System.getProperty(HTTP_AGENT);
    System.setProperty(HTTP_AGENT, USER_AGENT);
    try (Scanner scanner = new Scanner(new URL(requestUrl).openStream(),
        StandardCharsets.UTF_8.toString())) {
      scanner.useDelimiter("\\A");
      return scanner.hasNext() ? scanner.next() : StringUtils.EMPTY;
    } finally {
      if (sysUa != null) {
        System.setProperty(HTTP_AGENT, sysUa);
      }
    }
  }
}
