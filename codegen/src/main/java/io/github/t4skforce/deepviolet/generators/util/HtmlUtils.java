package io.github.t4skforce.deepviolet.generators.util;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HtmlUtils {
  private static final Logger LOG = LoggerFactory.getLogger(HtmlUtils.class);

  public static Optional<String> outerHtml(final CloseableHttpResponse response, final String css) {
    return elem(response, css).map(e -> e.outerHtml());
  }

  public static Optional<String> outerHtml(final HttpEntity entity, final String css) {
    return elem(entity, css).map(e -> e.outerHtml());
  }

  public static Optional<String> outerHtml(final String body, final String css) {
    return elem(body, css).map(e -> e.outerHtml());
  }

  public static Optional<String> html(final CloseableHttpResponse response, final String css) {
    return elem(response, css).map(e -> e.html());
  }

  public static Optional<String> html(final HttpEntity entity, final String css) {
    return elem(entity, css).map(e -> e.html());
  }

  public static Optional<String> html(final String body, final String css) {
    return elem(body, css).map(e -> e.html());
  }

  public static Optional<String> text(final CloseableHttpResponse response, final String css) {
    return elem(response, css).map(e -> e.text());
  }

  public static Optional<String> text(final HttpEntity entity, final String css) {
    return elem(entity, css).map(e -> e.text());
  }

  public static Optional<String> text(final String body, final String css) {
    return elem(body, css).map(e -> e.text());
  }

  public static Optional<Element> elem(final CloseableHttpResponse response, final String css) {
    return elem(response.getEntity(), css);
  }

  public static Optional<Element> elem(final HttpEntity entity, final String css) {
    return Optional.ofNullable(entity).map(m -> {
      try {
        return IOUtils.toString(m.getContent(), Charset.defaultCharset());
      } catch (IOException e) {
        LOG.error(e.getMessage(), e);
        return StringUtils.EMPTY;
      }
    }).filter(StringUtils::isNoneBlank).map(b -> elem(b, css)).orElseGet(Optional::empty);
  }

  public static Optional<Elements> elems(final CloseableHttpResponse response, final String css) {
    return elems(response.getEntity(), css);
  }

  public static Optional<Elements> elems(final HttpEntity entity, final String css) {
    return Optional.ofNullable(entity).map(m -> {
      try {
        return IOUtils.toString(m.getContent(), Charset.defaultCharset());
      } catch (IOException e) {
        LOG.error(e.getMessage(), e);
        return StringUtils.EMPTY;
      }
    }).filter(StringUtils::isNoneBlank).map(b -> elems(b, css)).orElseGet(Optional::empty);
  }

  public static Optional<Elements> elems(final String body, final String css) {
    return Optional.ofNullable(body).filter(StringUtils::isNoneBlank).map(b -> Jsoup.parse(b, "http://example.com/").select(css)).filter(Objects::nonNull);
  }

  public static Optional<Element> elem(final String body, final String css) {
    return Optional.ofNullable(body).map(b -> Jsoup.parse(b, "http://example.com/").select(css).first()).filter(Objects::nonNull);
  }
}
