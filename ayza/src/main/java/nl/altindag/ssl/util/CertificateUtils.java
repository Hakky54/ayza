/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericCertificateException;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.util.internal.IOUtils;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.internal.CollectorsUtils.toModifiableList;
import static nl.altindag.ssl.util.internal.CollectorsUtils.toUnmodifiableList;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotNull;

/**
 * @author Hakan Altindag
 */
public final class CertificateUtils {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final String P7B_HEADER = "-----BEGIN PKCS7-----";
    private static final String P7B_FOOTER = "-----END PKCS7-----";
    private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_FOOTER = "-----END CERTIFICATE-----";
    private static final Pattern PEM_PATTERN = Pattern.compile(PEM_HEADER + "(.*?)" + PEM_FOOTER, Pattern.DOTALL);
    private static final Pattern P7B_PATTERN = Pattern.compile(P7B_HEADER + "(.*?)" + P7B_FOOTER, Pattern.DOTALL);
    private static final String EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE = "Failed to load the certificate from the provided InputStream because it is null";
    private static final UnaryOperator<String> CERTIFICATE_NOT_FOUND_EXCEPTION_MESSAGE = certificatePath -> String.format("Failed to load the certificate from the classpath for the given path: [%s]", certificatePath);
    private static final String MAX_64_CHARACTER_LINE_SPLITTER = "(?<=\\G.{64})";

    private static final String EMPTY = "";

    private CertificateUtils() {}

    public static <T extends Certificate> String generateAlias(T certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate)
                    .getSubjectX500Principal()
                    .getName(X500Principal.CANONICAL)
                    .replace(" ", "-")
                    .replace(",", "_")
                    .replace("'", "")
                    .replaceAll("[.*\\\\/:()#]+", "")
                    .replaceAll("(-)\\1+", "$1");
        } else {
            return UUID.randomUUID().toString().toLowerCase(Locale.US);
        }
    }

    public static <T extends Certificate> Map<String, T> generateAliases(List<T> certificates) {
        Map<String, T> aliasToCertificate = new LinkedHashMap<>();
        for (T certificate : certificates) {
            String alias = generateUniqueAlias(certificate, aliasToCertificate::containsKey);
            aliasToCertificate.put(alias, certificate);
        }
        return Collections.unmodifiableMap(aliasToCertificate);
    }

    public static <T extends Certificate> String generateUniqueAlias(T certificate, Predicate<String> aliasPredicate) {
        String initialAlias = generateAlias(certificate);
        String alias = initialAlias;

        int counter = 0;
        while (aliasPredicate.test(alias)) {
            alias = String.format("%s-%d", initialAlias, counter);
            counter++;
        }

        return alias;
    }

    public static <T extends Certificate> void write(Path destination, T certificate) {
        try {
            byte[] encodedCertificate = certificate.getEncoded();
            IOUtils.write(destination, encodedCertificate);
        } catch (CertificateEncodingException e) {
            throw new GenericCertificateException(e);
        }
    }

    /**
     * Loads certificates from the classpath and maps it into a list of {@link Certificate}.
     * <br>
     * Supported input format: PEM, P7B and DER
     */
    public static List<Certificate> loadCertificate(String... certificatePaths) {
        return loadCertificate(certificatePath ->
                requireNotNull(
                        IOUtils.getResourceAsStream(certificatePath),
                        CERTIFICATE_NOT_FOUND_EXCEPTION_MESSAGE.apply(certificatePath)),
                certificatePaths
        );
    }

    /**
     * Loads certificates from the filesystem and maps it into a list of {@link Certificate}.
     * <br>
     * Supported input format: PEM, P7B and DER
     */
    public static List<Certificate> loadCertificate(Path... certificatePaths) {
        return loadCertificate(certificatePath -> {
            try {
                return Files.newInputStream(certificatePath, StandardOpenOption.READ);
            } catch (IOException exception) {
                throw new GenericIOException(exception);
            }
        }, certificatePaths);
    }

    /**
     * Loads certificates from multiple InputStreams and maps it into a list of {@link Certificate}.
     * <br>
     * Supported input format: PEM, P7B and DER
     */
    public static List<Certificate> loadCertificate(InputStream... certificateStreams) {
        return loadCertificate(certificateStream ->
                requireNotNull(certificateStream, EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE),
                certificateStreams
        );
    }

    private static <T> List<Certificate> loadCertificate(Function<T, InputStream> resourceMapper, T[] resources) {
        List<Certificate> certificates = new ArrayList<>();
        for (T resource : resources) {
            try (InputStream certificateStream = resourceMapper.apply(resource)) {
                certificates.addAll(parseCertificate(certificateStream));
            } catch (Exception e) {
                throw new GenericIOException(e);
            }
        }

        return Collections.unmodifiableList(certificates);
    }

    /**
     * Tries to map the InputStream to a list of {@link Certificate}.
     * It assumes that the content of the InputStream is either PEM, P7B or DER.
     * The InputStream will copied into an OutputStream so it can be read multiple times.
     */
    private static List<Certificate> parseCertificate(InputStream certificateStream) {
        List<Certificate> certificates;
        byte[] certificateData = IOUtils.copyToByteArray(certificateStream);
        String certificateContent = new String(certificateData, StandardCharsets.UTF_8);

        if (isPemFormatted(certificateContent)) {
            certificates = parsePemCertificate(certificateContent);
        } else if(isP7bFormatted(certificateContent)) {
            certificates = parseP7bCertificate(certificateContent);
        } else {
            certificates = parseDerCertificate(new ByteArrayInputStream(certificateData));
        }

        return certificates;
    }

    private static boolean isPemFormatted(String certificateContent) {
        return PEM_PATTERN.matcher(certificateContent).find();
    }

    private static boolean isP7bFormatted(String certificateContent) {
        return P7B_PATTERN.matcher(certificateContent).find();
    }

    /**
     * Parses PEM formatted certificates containing a
     * header as -----BEGIN CERTIFICATE----- and footer as -----END CERTIFICATE-----
     * or header as -----BEGIN PKCS7----- and footer as -----END PKCS7-----
     * with a base64 encoded data between the header and footer.
     */
    public static List<Certificate> parsePemCertificate(String certificateContent) {
        Matcher pemMatcher = PEM_PATTERN.matcher(certificateContent);
        return parseCertificate(pemMatcher);
    }

    /**
     * Parses P7B formatted certificates containing a
     * header as -----BEGIN PKCS7----- and footer as -----END PKCS7-----
     * with a base64 encoded data between the header and footer.
     */
    public static List<Certificate> parseP7bCertificate(String certificateContent) {
        Matcher p7bMatcher = P7B_PATTERN.matcher(certificateContent);
        return parseCertificate(p7bMatcher);
    }

    private static List<Certificate> parseCertificate(Matcher certificateMatcher) {
        List<Certificate> certificates = new ArrayList<>();
        while (certificateMatcher.find()) {
            String certificate = certificateMatcher.group(1);
            String sanitizedCertificate = certificate.replaceAll("[\\n|\\r]+", EMPTY).trim();
            byte[] decodedCertificate = Base64.getDecoder().decode(sanitizedCertificate);
            ByteArrayInputStream certificateAsInputStream = new ByteArrayInputStream(decodedCertificate);
            List<Certificate> parsedCertificates = CertificateUtils.parseDerCertificate(certificateAsInputStream);
            certificates.addAll(parsedCertificates);
            IOUtils.closeSilently(certificateAsInputStream);
        }

        return Collections.unmodifiableList(certificates);
    }

    public static List<Certificate> parseDerCertificate(InputStream certificateStream) {
        try(BufferedInputStream bufferedCertificateStream = new BufferedInputStream(certificateStream)) {
            return CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertificates(bufferedCertificateStream).stream()
                    .collect(toUnmodifiableList());
        } catch (CertificateException | IOException e) {
            return Collections.emptyList();
        }
    }

    public static List<X509Certificate> getJdkTrustedCertificates() {
        return Stream.of(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates().getAcceptedIssuers())
                .collect(toUnmodifiableList());
    }

    public static List<X509Certificate> getSystemTrustedCertificates() {
        return TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates()
                .map(X509TrustManager::getAcceptedIssuers)
                .map(Arrays::asList)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
    }

    public static List<X509Certificate> getCertificatesFromExternalSource(String url) {
        return CertificateExtractingClient.getInstance().get(url);
    }

    public static List<X509Certificate> getCertificatesFromExternalSource(Proxy proxy, String url) {
        return CertificateExtractingClient.builder()
                .withResolvedRootCa(true)
                .withProxy(proxy)
                .build()
                .get(url);
    }

    public static List<X509Certificate> getCertificatesFromExternalSource(Proxy proxy, PasswordAuthentication passwordAuthentication, String url) {
        return CertificateExtractingClient.builder()
                .withResolvedRootCa(true)
                .withProxy(proxy)
                .withPasswordAuthentication(passwordAuthentication)
                .build()
                .get(url);
    }

    public static List<String> getCertificatesFromExternalSourceAsPem(String url) {
        return getCertificatesFromExternalSource(url).stream()
                .map(CertificateUtils::convertToPem)
                .collect(toUnmodifiableList());
    }

    public static List<String> getCertificatesFromExternalSourceAsPem(Proxy proxy, String url) {
        return getCertificatesFromExternalSource(proxy, url).stream()
                .map(CertificateUtils::convertToPem)
                .collect(toUnmodifiableList());
    }

    public static List<String> getCertificatesFromExternalSourceAsPem(Proxy proxy, PasswordAuthentication passwordAuthentication, String url) {
        return getCertificatesFromExternalSource(proxy, passwordAuthentication, url).stream()
                .map(CertificateUtils::convertToPem)
                .collect(toUnmodifiableList());
    }

    public static Map<String, List<X509Certificate>> getCertificatesFromExternalSources(String... urls) {
        return getCertificatesFromExternalSources(Arrays.asList(urls));
    }

    public static Map<String, List<X509Certificate>> getCertificatesFromExternalSources(Proxy proxy, String... urls) {
        return getCertificatesFromExternalSources(proxy, Arrays.asList(urls));
    }

    public static Map<String, List<X509Certificate>> getCertificatesFromExternalSources(Proxy proxy, PasswordAuthentication passwordAuthentication, String... urls) {
        return getCertificatesFromExternalSources(proxy, passwordAuthentication, Arrays.asList(urls));
    }

    public static Map<String, List<X509Certificate>> getCertificatesFromExternalSources(List<String> urls) {
        return urls.stream()
                .distinct()
                .map(url -> new AbstractMap.SimpleEntry<>(url, getCertificatesFromExternalSource(url)))
                .collect(Collectors.collectingAndThen(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue, (key1, key2) -> key1, LinkedHashMap::new), Collections::unmodifiableMap));
    }

    public static Map<String, List<X509Certificate>> getCertificatesFromExternalSources(Proxy proxy, List<String> urls) {
        CertificateExtractingClient client = CertificateExtractingClient.builder()
                .withResolvedRootCa(true)
                .withProxy(proxy)
                .build();

        return urls.stream()
                .distinct()
                .map(url -> new AbstractMap.SimpleEntry<>(url, client.get(url)))
                .collect(Collectors.collectingAndThen(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue, (key1, key2) -> key1, LinkedHashMap::new), Collections::unmodifiableMap));
    }

    public static Map<String, List<X509Certificate>> getCertificatesFromExternalSources(Proxy proxy, PasswordAuthentication passwordAuthentication, List<String> urls) {
        CertificateExtractingClient client = CertificateExtractingClient.builder()
                .withResolvedRootCa(true)
                .withPasswordAuthentication(passwordAuthentication)
                .withProxy(proxy)
                .build();

        return urls.stream()
                .distinct()
                .map(url -> new AbstractMap.SimpleEntry<>(url, client.get(url)))
                .collect(Collectors.collectingAndThen(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue, (key1, key2) -> key1, LinkedHashMap::new), Collections::unmodifiableMap));
    }

    public static Map<String, List<String>> getCertificatesFromExternalSourcesAsPem(String... urls) {
        return getCertificatesFromExternalSourcesAsPem(Arrays.asList(urls));
    }

    public static Map<String, List<String>> getCertificatesFromExternalSourcesAsPem(Proxy proxy, String... urls) {
        return getCertificatesFromExternalSourcesAsPem(proxy, Arrays.asList(urls));
    }

    public static Map<String, List<String>> getCertificatesFromExternalSourcesAsPem(Proxy proxy, PasswordAuthentication passwordAuthentication, String... urls) {
        return getCertificatesFromExternalSourcesAsPem(proxy, passwordAuthentication, Arrays.asList(urls));
    }

    public static Map<String, List<String>> getCertificatesFromExternalSourcesAsPem(List<String> urls) {
        return CertificateUtils.getCertificatesFromExternalSources(urls).entrySet().stream()
                .collect(Collectors.collectingAndThen(Collectors.toMap(Map.Entry::getKey, entry -> CertificateUtils.convertToPem(entry.getValue()), (key1, key2) -> key1, LinkedHashMap::new), Collections::unmodifiableMap));
    }

    public static Map<String, List<String>> getCertificatesFromExternalSourcesAsPem(Proxy proxy, List<String> urls) {
        Map<String, List<String>> certificates = CertificateUtils.getCertificatesFromExternalSources(proxy, urls).entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> CertificateUtils.convertToPem(entry.getValue())));

        return Collections.unmodifiableMap(certificates);
    }

    public static Map<String, List<String>> getCertificatesFromExternalSourcesAsPem(Proxy proxy, PasswordAuthentication passwordAuthentication, List<String> urls) {
        return CertificateUtils.getCertificatesFromExternalSources(proxy, passwordAuthentication, urls).entrySet().stream()
                .collect(Collectors.collectingAndThen(Collectors.toMap(Map.Entry::getKey, entry -> CertificateUtils.convertToPem(entry.getValue()), (key1, key2) -> key1, LinkedHashMap::new), Collections::unmodifiableMap));
    }

    public static List<String> convertToPem(List<X509Certificate> certificates) {
        return certificates.stream()
                .map(CertificateUtils::convertToPem)
                .collect(toUnmodifiableList());
    }

    public static String convertToPem(Certificate certificate) {
        try {
            byte[] encodedCertificate = certificate.getEncoded();
            byte[] base64EncodedCertificate = Base64.getEncoder().encode(encodedCertificate);
            String parsedCertificate = new String(base64EncodedCertificate);

            List<String> certificateContainer = Stream.of(parsedCertificate.split(MAX_64_CHARACTER_LINE_SPLITTER))
                    .collect(toModifiableList());
            certificateContainer.add(0, PEM_HEADER);
            certificateContainer.add(PEM_FOOTER);

            if (certificate instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                X500Principal issuer = x509Certificate.getIssuerX500Principal();
                certificateContainer.add(0, String.format("issuer=%s", issuer.getName()));
                X500Principal subject = x509Certificate.getSubjectX500Principal();
                certificateContainer.add(0, String.format("subject=%s", subject.getName()));
            }

            return String.join(System.lineSeparator(), certificateContainer);
        } catch (CertificateEncodingException e) {
            throw new GenericCertificateException(e);
        }
    }

    public static <T extends Certificate> boolean isSelfSigned(T certificate) {
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (SignatureException e) {
            return false;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
            throw new GenericCertificateException(e);
        }
    }

}
