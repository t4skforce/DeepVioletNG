package io.github.t4skforce.deepviolet.build;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import io.github.t4skforce.deepviolet.json.CipherMapClassificationsJson;
import io.github.t4skforce.deepviolet.json.CipherMapJson;
import io.github.t4skforce.deepviolet.util.Downloader;

/**
 *
 * Reimplementation of
 * https://github.com/april/tls-table/blob/master/tls-table.py in Java
 *
 * @author t4skforce
 *
 */
public class CipherMapBuilder {

	private static String IANA_URL = "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml";
	private static String NSS_URL = "https://hg.mozilla.org/projects/nss/raw-file/tip/lib/ssl/sslproto.h";
	private static String OPENSSL_URL = "https://raw.githubusercontent.com/openssl/openssl/master/include/openssl/tls1.h";
	private static String GNUTLS_URL = "https://gitlab.com/gnutls/gnutls/raw/master/lib/algorithms/ciphersuites.c";

	private static Pattern REGEX_IANA = Pattern.compile(
			"<td[^>]*>(?<hex>0x[0-9|A-F]{2},0x[0-9|A-F]{2})</td[^>]*>[^<]*<td[^>]*>(?<name>TLS_[^\\s]+)</td[^>]*>",
			Pattern.DOTALL | Pattern.MULTILINE);

	private static Pattern REGEX_NSS = Pattern.compile("#\\s*define\\s+(?<name>TLS_[^\\s]+)\\s+(?<hex>0x[A-F|0-9]{4})",
			Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

	private static Pattern REGEX_OPENSSL = Pattern.compile(
			"#\\s*define\\s+TLS1_CK_(?<name>[^\\s]+)\\s+(?<hex>0x[A-F|0-9]{8})",
			Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

	private static Pattern REGEX_OPENSSL_NAMES = Pattern.compile(
			"#\\s*define\\s+TLS1_TXT_(?<key>[^\\s]+)\\s+\"(?<value>[^\"]+)\"",
			Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

	private static Pattern REGEX_GNUTLS_NAMES = Pattern.compile(
			"#\\s*define\\s*GNU(?<name>TLS_[^\\s]+)\\s*\\{\\s*(?<hex1>0x[A-F|0-9]{2})\\s*,\\s*(?<hex2>0x[A-F|0-9]{2})\\s*\\}",
			Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

	private File target;

	private CipherMapJson cipherMapJson = new CipherMapJson();

	private Map<String, String> ianaNameMap = new HashMap<>();

	private Consumer<String> logConsumer = m -> {};

	private Consumer<String> warnConsumer = m -> {};

	private Consumer<Exception> errorConsumer = e -> {};

	private CipherMapBuilder(File target) {
		this.target = target;
	}

	public static CipherMapBuilder builder(File target) {
		return new CipherMapBuilder(target);
	}

	public CipherMapBuilder parse() throws Exception {
		int cnt = 0;
		log("Fetching IANA definition "+IANA_URL);
		cnt = parseIANA();
		log("found "+cnt+" entries");
		log("Fetching NSS definition "+NSS_URL);
		parseNSS();
		log("found "+cnt+" entries");
		log("Fetching OpenSSL definition "+NSS_URL);
		parseOpenSSL();
		log("found "+cnt+" entries");
		log("Fetching GnuTLS definition "+NSS_URL);
		parseGnuTLS();
		log("found "+cnt+" entries");
		return this;
	}

	public CipherMapBuilder write() throws JsonGenerationException, JsonMappingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(MapperFeature.USE_ANNOTATIONS, true);
		ObjectWriter writer = mapper.writer(new DefaultPrettyPrinter());
		writer.writeValue(target, cipherMapJson);
		return this;
	}

	public CipherMapBuilder log(Consumer<String> logConsumer) {
		this.logConsumer = logConsumer;
		return this;
	}

	public CipherMapBuilder warn(Consumer<String> warnConsumer) {
		this.warnConsumer = warnConsumer;
		return this;
	}

	public CipherMapBuilder error(Consumer<Exception> errorConsumer) {
		this.errorConsumer = errorConsumer;
		return this;
	}

	private void log(String message) {
		this.logConsumer.accept(message);
	}

	private void warn(String message) {
		this.warnConsumer.accept(message);
	}

	private void error(Exception message) {
		this.errorConsumer.accept(message);
	}

	private int parseIANA() throws Exception {
		Matcher sources = REGEX_IANA.matcher(Downloader.get(IANA_URL));
		int cnt = 0;
		while (sources.find()) {
			String hex = sources.group("hex").trim().toUpperCase().replaceAll("X", "x");
			String name = sources.group("name").trim().toUpperCase();

			if (!cipherMapJson.containsKey(hex)) {
				cipherMapJson.put(hex, new CipherMapClassificationsJson());
			}
			CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
			cipher.setIana(name);

			cipherMapJson.put(hex, cipher);
			ianaNameMap.put(name, hex);
			cnt++;
		}

		return cnt;
	}

	private int parseNSS() throws Exception {
		int cnt = 0;
		Matcher sources = REGEX_NSS.matcher(Downloader.get(NSS_URL));
		while (sources.find()) {
			String hex = sources.group("hex").trim().toUpperCase().replaceAll("X", "x");
			hex = String.format("%s,0x%s", hex.substring(0, 4), hex.substring(4, 6));
			String name = sources.group("name").trim().toUpperCase();
			if (!cipherMapJson.containsKey(hex)) {
				warn("NSS code point " + hex + " (" + name + ") not in IANA registry");
				continue;
			}
			CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
			cipher.setNss(name);

			cnt++;
		}

		return cnt;
	}

	private int parseOpenSSL() throws Exception {
		int cnt = 0;
		String content = Downloader.get(OPENSSL_URL);

		// mapping e.g., ECDHE_RSA_WITH_AES_128_GCM_SHA256 ->
		// ECDHE-RSA-AES128-GCM-SHA256
		Map<String, String> mapping = new HashMap<>();
		Matcher sources = REGEX_OPENSSL_NAMES.matcher(content);
		while (sources.find()) {
			String key = sources.group("key").trim().toUpperCase();
			String value = sources.group("value").trim().toUpperCase();
			mapping.put(key, value);
		}

		sources = REGEX_OPENSSL.matcher(content);
		while (sources.find()) {
			String name = sources.group("name").trim().toUpperCase();
			name = mapping.get(name);
			String hex = sources.group("hex").trim().toUpperCase().replaceAll("X", "x");
			hex = String.format("0x%s,0x%s", hex.substring(6, 8), hex.substring(8, 10));

			if (!cipherMapJson.containsKey(hex)) {
				warn("OpenSSL code point " + hex + " (" + name + ") not in IANA registry");
				continue;
			}
			CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
			cipher.setOpenssl(name);

			cnt++;
		}

		return cnt;
	}

	private int parseGnuTLS() throws Exception {
		int cnt = 0;
		Matcher sources = REGEX_GNUTLS_NAMES.matcher(Downloader.get(GNUTLS_URL));
		while (sources.find()) {
			String hex = String.format("%s,%s", sources.group("hex1").trim().toUpperCase().replaceAll("X", "x"),
					sources.group("hex2").trim().toUpperCase().replaceAll("X", "x"));
			String name = sources.group("name").trim().toUpperCase();
			if (!cipherMapJson.containsKey(hex)) {
				warn("GnuTLS code point " + hex + " (" + name + ") not in IANA registry");
				continue;
			}
			CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
			cipher.setGnutls(name);
			cnt++;
		}

		return cnt;
	}

	public static void main(String[] args) throws Exception {
		CipherMapBuilder.builder(Paths.get(args[0],args[1]).toFile())
		.log(m -> {System.out.println("INFO: "+m);})
		.warn(m -> {System.out.println("WARN: "+m);})
		.error(e -> {
			System.out.println("ERROR: "+e.getMessage());
			e.printStackTrace();
		}).parse().write();
	}
}
