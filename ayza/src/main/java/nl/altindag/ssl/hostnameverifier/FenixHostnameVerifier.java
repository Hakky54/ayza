/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package nl.altindag.ssl.hostnameverifier;

import nl.altindag.laleler.StringUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static nl.altindag.ssl.hostnameverifier.HostnameCommon.canParseAsIpAddress;
import static nl.altindag.ssl.hostnameverifier.Hostnames.toCanonicalHost;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.HostnameVerifierUtils HostnameVerifierUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * </p>
 * This verifier does not accept addresses in the subjectDN:commonName attribute
 * and it will not verify names or wildcards against the Public Suffix List.
 * Therefore use of wildcards is not limited to subdomains.
 * </p>
 *
 * This HostnameVerifier is copied from OkHttp library, see here for the original content:
 * - https://github.com/square/okhttp/blob/69ae7f3e10dae0554f3181edaa52bcd77ee448ab/okhttp/src/jvmMain/kotlin/okhttp3/internal/tls/OkHostnameVerifier.kt#L1
 */
public final class FenixHostnameVerifier implements HostnameVerifier {

    private static final HostnameVerifier INSTANCE = new FenixHostnameVerifier();
    private static final int ALT_DNS_NAME = 2;
    private static final int ALT_IPA_NAME = 7;

    private FenixHostnameVerifier() {}

    public static HostnameVerifier getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean verify(String host, SSLSession sslSession) {
        if (!isAscii(host)) {
            return false;
        }

        Optional<X509Certificate> peerCertificate = getPeerCertificate(sslSession);
        return peerCertificate.isPresent() && verify(host, peerCertificate.get());
    }

    /**
     * Returns true if the [String] is ASCII encoded.
     */
    private boolean isAscii(String value) {
        return StandardCharsets.US_ASCII.newEncoder().canEncode(value);
    }

    /**
     * Returns the first certificate from the peer certificates if present.
     */
    private Optional<X509Certificate> getPeerCertificate(SSLSession sslSession) {
        try {
            return Arrays.stream(sslSession.getPeerCertificates())
                    .filter(Objects::nonNull)
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .findFirst();
        } catch (SSLPeerUnverifiedException e) {
            return Optional.empty();
        }
    }

    private boolean verify(String host, X509Certificate certificate) {
        if (canParseAsIpAddress(host)) {
            return verifyIpAddress(host, certificate);
        } else {
            return verifyHostname(host, certificate);
        }
    }

    /**
     * Returns true if [certificate] matches [hostname].
     */
    private boolean verifyIpAddress(String ipAddress, X509Certificate certificate) {
        String canonicalIpAddress = toCanonicalHost(ipAddress);
        if (canonicalIpAddress == null) {
            return false;
        }

        List<String> subjectAltNames = getSubjectAltNames(certificate, ALT_IPA_NAME);
        return subjectAltNames.stream().anyMatch(subjectAltName -> canonicalIpAddress.equals(toCanonicalHost(subjectAltName)));
    }

    private List<String> getSubjectAltNames(X509Certificate certificate, int type) {
        try {
            Collection<List<?>> subjectAlternativeNames = Optional.ofNullable(certificate.getSubjectAlternativeNames())
                    .orElseGet(Collections::emptyList);

            return subjectAlternativeNames.stream()
                    .filter(Objects::nonNull)
                    .filter(subjectAlternativeName -> subjectAlternativeName.size() == 2)
                    .filter(subjectAlternativeName -> subjectAlternativeName.get(0) instanceof Integer && ((Integer) subjectAlternativeName.get(0)) == type)
                    .map(subjectAlternativeName -> subjectAlternativeName.get(1))
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(Collectors.toList());

        } catch (CertificateParsingException exception) {
            return Collections.emptyList();
        }
    }

    private boolean verifyHostname(String hostname, X509Certificate certificate) {
        List<String> subjectAltNames = getSubjectAltNames(certificate, ALT_DNS_NAME);
        return subjectAltNames.stream().anyMatch(subjectAltName -> verifyHostname(hostname, subjectAltName));
    }

    /**
     * Returns true if [hostname] matches the domain name pattern.
     *
     * @param hostname lower-case host name.
     * @param domainNamePattern domain name pattern from certificate. Maybe a wildcard pattern such as
     *     `*.android.com`.
     */
    private boolean verifyHostname(String hostname, String domainNamePattern) {
        if (isHostnameInValid(hostname) || isHostnameInValid(domainNamePattern)) {
            return false;
        }

        String resultingHostname = toAbsolute(hostname);
        String resultingDomainNamePattern = toAbsolute(domainNamePattern);
        // Hostname and pattern are now absolute domain names.

        resultingHostname = asciiToLowercase(resultingHostname);
        resultingDomainNamePattern = asciiToLowercase(resultingDomainNamePattern);
        // Hostname and pattern are now in lower case -- domain names are case-insensitive.

        if (!resultingDomainNamePattern.contains("*")) {
            // Not a wildcard pattern -- hostname and pattern must match exactly.
            return resultingHostname.equals(resultingDomainNamePattern);
        }

        // Wildcard pattern
        return verifyWildcardPattern(resultingHostname, resultingDomainNamePattern);
    }

    private boolean isHostnameInValid(String hostname) {
        return StringUtils.isBlank(hostname) || hostname.startsWith(".") || hostname.endsWith("..");
    }

    /**
     * Normalize hostname by turning it into absolute domain names if it is not
     * yet absolute. This is needed because server certificates do not normally contain absolute
     * names, but they should be treated as absolute. At the same time, any hostname
     * presented to this method should also be treated as absolute for the purposes of matching
     * to the server certificate.
     *   www.android.com  matches www.android.com
     *   www.android.com  matches www.android.com.
     *   www.android.com. matches www.android.com.
     *   www.android.com. matches www.android.com
     */
    String toAbsolute(String hostname) {
        String absoluteHostname = hostname;
        if (!absoluteHostname.endsWith(".")) {
            absoluteHostname += ".";
        }
        return absoluteHostname;
    }

    /**
     * This is like [toLowerCase] except that it does nothing if this contains any non-ASCII
     * characters. We want to avoid lower casing special chars like U+212A (Kelvin symbol) because
     * they can return ASCII characters that match real hostnames.
     */
    private String asciiToLowercase(String value) {
        return isAscii(value) ? value.toLowerCase(Locale.US) : value;
    }

    /**
     * WILDCARD PATTERN RULES:
     * 1. Asterisk (*) is only permitted in the left-most domain name label and must be the
     *    only character in that label (i.e., must match the whole left-most label).
     *    For example, *.example.com is permitted, while *a.example.com, a*.example.com,
     *    a*b.example.com, a.*.example.com are not permitted.
     * 2. Asterisk (*) cannot match across domain name labels.
     *    For example, *.example.com matches test.example.com but does not match
     *    sub.test.example.com.
     * 3. Wildcard patterns for single-label domain names are not permitted.
     */
    @SuppressWarnings("RedundantIfStatement")
    private boolean verifyWildcardPattern(String hostname, String domainNamePattern) {
        if (!domainNamePattern.startsWith("*.") || domainNamePattern.indexOf("*", 1) != -1) {
            // Asterisk (*) is only permitted in the left-most domain name label and must be the only
            // character in that label
            return false;
        }

        // Optimization: check whether hostname is too short to match the pattern. hostName must be at
        // least as long as the pattern because asterisk must match the whole left-most label and
        // hostname starts with a non-empty label. Thus, asterisk has to match one or more characters.
        if (hostname.length() < domainNamePattern.length()) {
            return false; // Hostname too short to match the pattern.
        }

        if ("*.".equals(domainNamePattern)) {
            return false; // Wildcard pattern for single-label domain name -- not permitted.
        }

        // Hostname must end with the region of pattern following the asterisk.
        String suffix = domainNamePattern.substring(1);
        if (!hostname.endsWith(suffix)) {
            return false; // Hostname does not end with the suffix.
        }

        // Check that asterisk did not match across domain name labels.
        int suffixStartIndexInHostname = hostname.length() - domainNamePattern.length();
        if (suffixStartIndexInHostname > 0 && hostname.lastIndexOf(".", suffixStartIndexInHostname - 1) != -1) {
            return false; // Asterisk is matching across domain name labels -- not permitted.
        }

        // Hostname matches pattern.
        return true;
    }

}
