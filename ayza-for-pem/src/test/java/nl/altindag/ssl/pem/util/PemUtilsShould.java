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
package nl.altindag.ssl.pem.util;

import nl.altindag.laleler.IOUtils;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.pem.exception.CertificateParseException;
import nl.altindag.ssl.pem.exception.PemParseException;
import nl.altindag.ssl.pem.exception.PrivateKeyParseException;
import nl.altindag.ssl.pem.exception.PublicKeyParseException;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;

/**
 * @author Hakan Altindag
 */
@SuppressWarnings("SameParameterValue")
@ExtendWith(MockitoExtension.class)
class PemUtilsShould {

    private static final String PEM_LOCATION = "pem/";
    private static final String TEST_RESOURCES_LOCATION = "src/test/resources/";
    public static final char[] DEFAULT_PASSWORD = "secret".toCharArray();

    @Test
    void parseSingleTrustMaterialFromContent() {
        String certificateContent = getResourceContent(PEM_LOCATION + "github-certificate.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void parseSingleTrustMaterialAsOpenSslTrustedCertificateFormatFromContent() {
        String certificateContent = getResourceContent(PEM_LOCATION + "alternative-certificate-type.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void parseMultipleTrustMaterialsFromContentAsMultipleStrings() {
        String certificateContentOne = getResourceContent(PEM_LOCATION + "github-certificate.pem");
        String certificateContentTwo = getResourceContent(PEM_LOCATION + "stackexchange.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContentOne, certificateContentTwo);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void parseMultipleTrustMaterialsFromContentAsSingleString() {
        String certificateContent = getResourceContent(PEM_LOCATION + "multiple-certificates.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadSingleTrustMaterialFromClassPathAsSingleFile() {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(PEM_LOCATION + "github-certificate.pem");

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsFromClassPathAsMultipleFiles() {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(
                PEM_LOCATION + "github-certificate.pem",
                PEM_LOCATION + "stackexchange.pem"
        );

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsFromClassPathAsSingleFile() {
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(PEM_LOCATION + "multiple-certificates.pem");

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadSingleTrustMaterialWithPathFromDirectoryAsSingleFile() {
        Path certificatePath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION + "github-certificate.pem").toAbsolutePath();

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsMultipleFiles() {
        Path certificatePathOne = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "github-certificate.pem").toAbsolutePath();
        Path certificatePathTwo = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "stackexchange.pem").toAbsolutePath();

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePathOne, certificatePathTwo);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsWithPathFromDirectoryAsSingleFile() {
        Path certificatePath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "multiple-certificates.pem");

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certificatePath);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadingNonExistingTrustMaterialFromDirectoryThrowsException() {
        Path nonExistingCertificate = Paths.get("somewhere-in-space.pem");
        assertThatThrownBy(() -> PemUtils.loadTrustMaterial(nonExistingCertificate))
                .isInstanceOf(GenericIOException.class)
                .hasMessageContaining("java.nio.file.NoSuchFileException: somewhere-in-space.pem");
    }

    @Test
    void loadSingleTrustMaterialFromSingleInputStream() throws IOException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "github-certificate.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStream);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadMultipleTrustMaterialsFromMultipleInputStream() throws IOException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStreamOne = getResource(PEM_LOCATION + "github-certificate.pem");
            InputStream inputStreamTwo = getResource(PEM_LOCATION + "stackexchange.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStreamOne, inputStreamTwo);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void loadMultipleTrustMaterialsFromSingleInputStream() throws IOException {
        X509ExtendedTrustManager trustManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "multiple-certificates.pem")) {
            trustManager = PemUtils.loadTrustMaterial(inputStream);
        }

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void loadUnencryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromDirectory() {
        Path identityPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "unencrypted-identity.pem").toAbsolutePath();

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromInputStream() throws IOException {
        X509ExtendedKeyManager keyManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "unencrypted-identity.pem")) {
            keyManager = PemUtils.loadIdentityMaterial(inputStream);
        }

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem",
                PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem"
        );

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityFromDirectory() {
        Path certificatePath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "splitted-unencrypted-identity-containing-certificate.pem").toAbsolutePath();
        Path privateKeyPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "splitted-unencrypted-identity-containing-private-key.pem").toAbsolutePath();

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificatePath, privateKeyPath);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyAndCertificateAsIdentityInputStream() throws IOException {
        try(InputStream certificateStream = getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem");
            InputStream privateKeyStream = getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem")) {
            X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificateStream, privateKeyStream);
            assertThat(keyManager).isNotNull();
        }
    }

    @Test
    void loadEncryptedPrivateKeyAndCertificateAsIdentityFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "splitted-encrypted-identity-containing-certificate.pem",
                PEM_LOCATION + "splitted-encrypted-identity-containing-private-key.pem",
                DEFAULT_PASSWORD
        );

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedPrivateKeyShouldFailWhenMissingPassword() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "splitted-encrypted-identity-containing-certificate.pem",
                PEM_LOCATION + "splitted-encrypted-identity-containing-private-key.pem",
                null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("A password is mandatory with an encrypted key");
    }

    @Test
    void loadRsaEncryptedPrivateKeyShouldFailWhenMissingPassword() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(
                PEM_LOCATION + "encrypted-rsa-identity.pem",
                        (char[]) null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("A password is mandatory with an encrypted key");
    }

    @Test
    void loadRsaUnencryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "rsa-unencrypted-identity.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadRsaEncryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-rsa-identity.pem", DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEcUnencryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-ec-identity.pem", DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEcEncryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-ec-identity.pem", DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromClassPath() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "encrypted-identity.pem", DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromDirectory() {
        Path identityPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "encrypted-identity.pem").toAbsolutePath();

        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(identityPath, DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromInputStream() throws IOException {
        X509ExtendedKeyManager keyManager;
        try(InputStream inputStream = getResource(PEM_LOCATION + "encrypted-identity.pem")) {
            keyManager = PemUtils.loadIdentityMaterial(inputStream, DEFAULT_PASSWORD);
        }

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnencryptedIdentityMaterialFromClassPathWhichFirstContainsTheCertificate() {
        X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity-with-certificate-first.pem");

        assertThat(keyManager).isNotNull();
    }

    @Test
    void parseEncryptedIdentityMaterialFromContent() {
        String identityContent = getResourceContent(PEM_LOCATION + "encrypted-identity.pem");

        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent, DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void parseUnencryptedPrivateKeyAndCertificateAsIdentity() {
        String certificateContent = getResourceContent(PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem");
        String privateKeyContent = getResourceContent(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem");

        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(certificateContent, privateKeyContent, null);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void throwGenericIOExceptionWhenInputStreamCanNotBeClosed() throws IOException {
        InputStream certificateStream = spy(getResource(PEM_LOCATION + "github-certificate.pem"));

        doThrow(new IOException("KABOOM!!!"))
                .when(certificateStream)
                .close();

        assertThatThrownBy(() -> PemUtils.loadTrustMaterial(certificateStream))
                .isInstanceOf(GenericIOException.class)
                .hasRootCauseMessage("KABOOM!!!");
    }

    @Test
    void loadUnencryptedPrivateKeyFromClassPath() {
        PrivateKey privateKey = PemUtils.loadPrivateKey(PEM_LOCATION + "unencrypted-identity.pem");

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyFromDirectory() {
        Path identityPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "unencrypted-identity.pem").toAbsolutePath();

        PrivateKey privateKey = PemUtils.loadPrivateKey(identityPath);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyFromInputStream() throws IOException {
        PrivateKey privateKey;
        try(InputStream inputStream = getResource(PEM_LOCATION + "unencrypted-identity.pem")) {
            privateKey = PemUtils.loadPrivateKey(inputStream);
        }

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadRsaUnencryptedPrivateKeyFromClassPath() {
        PrivateKey privateKey = PemUtils.loadPrivateKey(PEM_LOCATION + "rsa-unencrypted-identity.pem");

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadRsaEncryptedPrivateKeyFromClassPath() {
        PrivateKey privateKey = PemUtils.loadPrivateKey(PEM_LOCATION + "encrypted-rsa-identity.pem", DEFAULT_PASSWORD);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadEcUnencryptedPrivateKeyFromClassPath() {
        PrivateKey privateKey = PemUtils.loadPrivateKey(PEM_LOCATION + "unencrypted-ec-identity.pem", DEFAULT_PASSWORD);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadEcEncryptedPrivateKeyFromClassPath() {
        PrivateKey privateKey = PemUtils.loadPrivateKey(PEM_LOCATION + "encrypted-ec-identity.pem", DEFAULT_PASSWORD);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadEncryptedPrivateKeyFromClassPath() {
        PrivateKey privateKey = PemUtils.loadPrivateKey(PEM_LOCATION + "encrypted-identity.pem", DEFAULT_PASSWORD);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadEncryptedPrivateKeyFromDirectory() {
        Path identityPath = Paths.get(TEST_RESOURCES_LOCATION + PEM_LOCATION, "encrypted-identity.pem").toAbsolutePath();

        PrivateKey privateKey = PemUtils.loadPrivateKey(identityPath, DEFAULT_PASSWORD);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadEncryptedPrivateKeyFromInputStream() throws IOException {
        PrivateKey privateKey;
        try(InputStream inputStream = getResource(PEM_LOCATION + "encrypted-identity.pem")) {
            privateKey = PemUtils.loadPrivateKey(inputStream, DEFAULT_PASSWORD);
        }

        assertThat(privateKey).isNotNull();
    }

    @Test
    void loadUnencryptedPrivateKeyFromClassPathWhichFirstContainsTheCertificate() {
        PrivateKey privateKey = PemUtils.loadPrivateKey(PEM_LOCATION + "unencrypted-identity-with-certificate-first.pem");

        assertThat(privateKey).isNotNull();
    }

    @Test
    void parseEncryptedPrivateKeyFromContent() {
        String identityContent = getResourceContent(PEM_LOCATION + "encrypted-identity.pem");

        PrivateKey privateKey = PemUtils.parsePrivateKey(identityContent, DEFAULT_PASSWORD);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void parseUnencryptedPrivateKeyFromContent() {
        String identityContent = getResourceContent(PEM_LOCATION + "unencrypted-identity.pem");

        PrivateKey privateKey = PemUtils.parsePrivateKey(identityContent);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void extractPublicKeyFromPrivateKey() {
        List<String> privateKeyFilePaths = List.of(PEM_LOCATION + "encrypted-ec-identity.pem", PEM_LOCATION + "encrypted-identity.pem", PEM_LOCATION + "encrypted-rsa-identity.pem", PEM_LOCATION + "rsa-unencrypted-identity.pem", PEM_LOCATION + "unencrypted-ec-identity.pem", PEM_LOCATION + "unencrypted-identity.pem");
        for (String privateKeyFilePath : privateKeyFilePaths) {
            String identityContent = getResourceContent(privateKeyFilePath);
            PrivateKey privateKey = PemUtils.parsePrivateKey(identityContent, DEFAULT_PASSWORD);
            PublicKey publicKey = PemUtils.extractPublicKey(privateKey);

            assertThat(publicKey).isNotNull();
        }
    }

    @Test
    void parseSingleTrustMaterialFromContentAsAsOneLiner() {
        String certificateContent = getResourceContent(PEM_LOCATION + "one-liner-stackexchange.pem");

        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void parseMultipleTrustMaterialsFromContentAsSingleStringAndAsOneLiner() {
        String certificateContent = getResourceContent(PEM_LOCATION + "one-liner-multiple-certificates.pem");

        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(3);
    }

    @Test
    void parseMultipleTrustMaterialsFromContentAsOneLiner() {
        String certificateContentOne = getResourceContent(PEM_LOCATION + "one-liner-github-certificate.pem");
        String certificateContentTwo = getResourceContent(PEM_LOCATION + "one-liner-stackexchange.pem");

        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContentOne, certificateContentTwo);
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void parseSingleTrustMaterialAsOpenSslTrustedCertificateFormatFromContentAsOneLiner() {
        String certificateContent = getResourceContent(PEM_LOCATION + "one-liner-alternative-certificate-type.pem");
        X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(certificateContent);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void loadEcEncryptedIdentityMaterialFromContentAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-encrypted-ec-identity.pem");
        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent, DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadEncryptedIdentityMaterialFromContentAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-encrypted-identity.pem");
        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent, DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadRsaDesEde3CbcEncryptedIdentityMaterialFromContentAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-encrypted-rsa-des-ede3-cbc-identity.pem");
        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent, DEFAULT_PASSWORD);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadRsaAes256CbcEncryptedPrivateKeyFromContentAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-encrypted-rsa-aes-256-cbc-private-key.pem");
        PrivateKey privateKey = PemUtils.parsePrivateKey(identityContent, DEFAULT_PASSWORD);

        assertThat(privateKey).isNotNull();
    }

    @Test
    void throwsIllegalArgumentExceptionWhenUnsupportedEncryptedRsaPrivateKeyIsProvidedAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-encrypted-rsa-faulty-private-key.pem");
        assertThatThrownBy(() -> PemUtils.parsePrivateKey(identityContent, DEFAULT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("The provided encrypted private key is not supported. Supported formats are: [AES-256-CBC,DES-EDE3-CBC]");
    }

    @Test
    void loadUnEncryptedRsaIdentityMaterialFromContentAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-unencrypted-rsa-identity.pem");
        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnEncryptedEcIdentityMaterialFromContentAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-unencrypted-ec-identity.pem");
        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent, null);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void loadUnEncryptedIdentityMaterialFromContentAsOneLiner() {
        String identityContent = getResourceContent(PEM_LOCATION + "one-liner-unencrypted-identity.pem");
        X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(identityContent, null);

        assertThat(keyManager).isNotNull();
    }

    @Test
    void returnEmptyForUnknownPrivateKeyInfo() {
        Optional<PrivateKeyInfo> privateKeyInfo = PemUtils.extractPrivateKeyInfo(new Object(), "".toCharArray());
        assertThat(privateKeyInfo).isEmpty();
    }

    @Test
    void returnEmptyForUnknownCertificate() {
        Optional<X509Certificate> certificate = PemUtils.extractCertificate(new Object());
        assertThat(certificate).isEmpty();
    }

    @Test
    void throwsIllegalArgumentExceptionWhenCertificateCannotBeFoundFromTheClasspath() {
        assertThatThrownBy(() -> PemUtils.loadCertificate("non-existing-directory/non-existing-certificate.pem"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the classpath for the given path: [non-existing-directory/non-existing-certificate.pem]");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenInputStreamIsNullWhileLoadingCertificate() {
        assertThatThrownBy(() -> PemUtils.loadCertificate((InputStream) null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the provided InputStream because it is null");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenIdentityCannotBeFoundFromTheClasspath() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial("non-existing-directory/non-existing-certificate.pem", "non-existing-directory/non-existing-certificate.pem", DEFAULT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the classpath for the given path: [non-existing-directory/non-existing-certificate.pem]");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenInputStreamIsNullWhileLoadingIdentity() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(null, (InputStream) null, DEFAULT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the provided InputStream because it is null");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenIdentityCannotBeFoundFromTheClasspathWhileUsingPrivateKeyAndChainCombined() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial("non-existing-directory/non-existing-certificate.pem", DEFAULT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the classpath for the given path: [non-existing-directory/non-existing-certificate.pem]");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenInputStreamIsNullWhileLoadingIdentityWhileUsingPrivateKeyAndChainCombined() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial((InputStream) null, DEFAULT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the provided InputStream because it is null");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenIdentityCannotBeFoundFromTheClasspathWhileLoadingThePrivateKey() {
        assertThatThrownBy(() -> PemUtils.loadPrivateKey("non-existing-directory/non-existing-certificate.pem", DEFAULT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the classpath for the given path: [non-existing-directory/non-existing-certificate.pem]");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenInputStreamIsNullWhileLoadingIdentityWhileLoadingThePrivateKey() {
        assertThatThrownBy(() -> PemUtils.loadPrivateKey((InputStream) null, DEFAULT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to load the certificate from the provided InputStream because it is null");
    }

    @Test
    void throwGenericIOExceptionWhenInputStreamCanNotBeClosedWhenLoadingIdentity() throws IOException {
        InputStream identityStream = spy(getResource(PEM_LOCATION + "encrypted-identity.pem"));
        String identityContent = getResourceContent(PEM_LOCATION + "encrypted-identity.pem");

        try (MockedStatic<IOUtils> ioUtilsMockedStatic = mockStatic(IOUtils.class)) {
            ioUtilsMockedStatic.when(() -> IOUtils.getContent(eq(identityStream), any(Function.class))).thenReturn(identityContent);

            doThrow(new IOException("KABOOM!!!"))
                    .when(identityStream)
                    .close();

            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(identityStream, DEFAULT_PASSWORD))
                    .isInstanceOf(GenericIOException.class)
                    .hasRootCauseMessage("KABOOM!!!");
        }
    }

    @Test
    void throwGenericIOExceptionWhenInputStreamCanNotBeClosedWhenLoadingPrivateKey() throws IOException {
        InputStream identityStream = spy(getResource(PEM_LOCATION + "encrypted-identity.pem"));
        String identityContent = getResourceContent(PEM_LOCATION + "encrypted-identity.pem");

        try (MockedStatic<IOUtils> ioUtilsMockedStatic = mockStatic(IOUtils.class)) {
            ioUtilsMockedStatic.when(() -> IOUtils.getContent(identityStream)).thenReturn(identityContent);

            doThrow(new IOException("KABOOM!!!"))
                    .when(identityStream)
                    .close();

            assertThatThrownBy(() -> PemUtils.loadPrivateKey(identityStream, DEFAULT_PASSWORD))
                    .isInstanceOf(GenericIOException.class)
                    .hasRootCauseMessage("KABOOM!!!");
        }
    }

    @Test
    void throwGenericIOExceptionWhenInputStreamCanNotBeClosedWhenCertificateChainAndPrivateKey() throws IOException {
        InputStream certificateChainStream = spy(getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem"));
        InputStream privateKeyStream = spy(getResource(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem"));
        String certificateChainContent = getResourceContent(PEM_LOCATION + "splitted-unencrypted-identity-containing-certificate.pem");
        String privateKeyContent = getResourceContent(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem");

        try (MockedStatic<IOUtils> ioUtilsMockedStatic = mockStatic(IOUtils.class)) {
            ioUtilsMockedStatic.when(() -> IOUtils.getContent(eq(certificateChainStream), any(Function.class))).thenReturn(certificateChainContent);
            ioUtilsMockedStatic.when(() -> IOUtils.getContent(eq(privateKeyStream), any(Function.class))).thenReturn(privateKeyContent);

            doThrow(new IOException("KABOOM!!!"))
                    .when(certificateChainStream)
                    .close();

            doThrow(new IOException("KABOOM!!!"))
                    .when(privateKeyStream)
                    .close();

            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(certificateChainStream, privateKeyStream))
                    .isInstanceOf(GenericIOException.class)
                    .hasRootCauseMessage("KABOOM!!!");
        }
    }

    @Test
    void throwPrivateKeyParseExceptionWhenAnUnknownPrivateKeyHasBeenSupplied() throws IOException {
        try(InputStream inputStream = new ByteArrayInputStream("Hello there friend!".getBytes(StandardCharsets.UTF_8))) {
            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(inputStream))
                    .isInstanceOf(PrivateKeyParseException.class)
                    .hasMessage("Received an unsupported private key type");
        }
    }

    @Test
    void throwExceptionWhenParseTrustMaterialIsCalledWithoutValidCertificate() {
        assertThatThrownBy(() -> PemUtils.parseTrustMaterial(""))
                .isInstanceOf(CertificateParseException.class)
                .hasMessage("Received an unsupported certificate type");
    }

    @Test
    void throwPublicKeyParseExceptionWhenPublicKeyIsMissing() {
        assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(PEM_LOCATION + "splitted-unencrypted-identity-containing-private-key.pem"))
                .hasMessageContaining("Received an unsupported certificate type");
    }

    @Test
    void throwCertificateParseExceptionWhenCertificateExceptionIsThrown() throws CertificateException {
        String certificateContent = getResourceContent(PEM_LOCATION + "github-certificate.pem");

        JcaX509CertificateConverter certificateConverter = mock(JcaX509CertificateConverter.class);
        PemUtils pemUtils = new PemUtils(new BouncyCastleProvider(), mock(JcaPEMKeyConverter.class), certificateConverter);

        try(MockedStatic<PemUtils> pemUtilsMockedStatic = mockStatic(PemUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getInstance".equals(method.getName()) && method.getParameterCount() == 0) {
                return pemUtils;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            doThrow(new CertificateException("KABOOOM!!!"))
                    .when(certificateConverter)
                    .getCertificate(any(X509CertificateHolder.class));

            assertThatThrownBy(() -> PemUtils.parseCertificate(certificateContent))
                    .isInstanceOf(CertificateParseException.class)
                    .hasMessageContaining("KABOOOM!!!");
        }
    }

    @Test
    void throwPrivateKeyParseExceptionWhenPEMExceptionIsThrown() throws PEMException {
        String identityContent = getResourceContent(PEM_LOCATION + "unencrypted-identity.pem");

        JcaPEMKeyConverter keyConverter = mock(JcaPEMKeyConverter.class);
        PemUtils pemUtils = new PemUtils(new BouncyCastleProvider(), keyConverter, mock(JcaX509CertificateConverter.class));

        try(MockedStatic<PemUtils> pemUtilsMockedStatic = mockStatic(PemUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getInstance".equals(method.getName()) && method.getParameterCount() == 0) {
                return pemUtils;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            doThrow(new PEMException("KABOOOM!!!"))
                    .when(keyConverter)
                    .getPrivateKey(any(PrivateKeyInfo.class));

            assertThatThrownBy(() -> PemUtils.parsePrivateKey(identityContent))
                    .isInstanceOf(PrivateKeyParseException.class)
                    .hasMessageContaining("KABOOOM!!!");
        }
    }

    @Test
    void throwPrivateKeyParseExceptionWhenInvalidPrivateKeyContentIsSupplied() {
        String invalidPrivateKey = "" +
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIy3Fposf+2ccCAggA\n" +
                "FHeRMpMdlCLXw78iQ6HjJw==\n" +
                "-----END ENCRYPTED PRIVATE KEY-----";

        assertThatThrownBy(() -> PemUtils.parseIdentityMaterial(invalidPrivateKey, null))
                .isInstanceOf(PemParseException.class)
                .hasMessageContaining("problem parsing ENCRYPTED PRIVATE KEY");
    }

    @Test
    void throwPemParseExceptionWhenInvalidCertificateContentIsSupplied() {
        String invalidCertificate = "" +
                "-----BEGIN CERTIFICATE-----\n" +
                "MwdGrM6kt0lfJy/gvGVsgIKZocHdedPeECqAtq7FAJYanOsjNN9RbBOGhbwq0/FP\n" +
                "CC01zojqS10nGowxzOiqyB4m6wytmzf0QwjpMw==\n" +
                "-----END CERTIFICATE-----";

        assertThatThrownBy(() -> PemUtils.parseTrustMaterial(invalidCertificate))
                .isInstanceOf(PemParseException.class);
    }

    @Test
    void throwPrivateKeyParseExceptionWhenInvalidPasswordForEncryptedPrivateKeyContentIsSuppliedA() {
        String invalidPrivateKey = getResourceContent(PEM_LOCATION + "encrypted-rsa-identity.pem");
        char[] keyPassword = "test".toCharArray();

        assertThatThrownBy(() -> PemUtils.parsePrivateKey(invalidPrivateKey, keyPassword))
                .isInstanceOf(PemParseException.class)
                .hasMessageContaining("exception using cipher - please check password and data");
    }

    @Test
    void throwGenericKeyStoreWhenSetKeyEntryThrowsKeyStoreException() throws KeyStoreException {
        KeyStore keyStore = mock(KeyStore.class);
        doThrow(new KeyStoreException("lazy")).when(keyStore).setKeyEntry(anyString(), any(Key.class), any(), any());

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 0) {
                return keyStore;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            assertThatThrownBy(() -> PemUtils.loadIdentityMaterial(PEM_LOCATION + "unencrypted-identity.pem"))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasMessageContaining("lazy");
        }
    }

    @Test
    void throwsPublicKeyParseExceptionForUnknownPrivateKeyWhenAttemptingToExtractPublicKey() {
        assertThatThrownBy(() -> PemUtils.extractPublicKey(null))
                .isInstanceOf(PublicKeyParseException.class);
    }

    @Test
    void throwsPublicKeyParseExceptionWhenUnableToExtractPublicKeyFromPrivateKey() {
        // PKCS#8 - ED25519
        String privateKeyContent =
                "-----BEGIN PRIVATE KEY-----\n" +
			    "MC4CAQAwBQYDK2VwBCIEIA5tsa4jA+q4iWoJXeFggOs1qrbloeNFM0/2SjtKWYLR\n" +
			    "-----END PRIVATE KEY-----";
        PrivateKey privateKey = PemUtils.parsePrivateKey(privateKeyContent);

        assertThatThrownBy(() -> PemUtils.extractPublicKey(privateKey))
                .isInstanceOf(PublicKeyParseException.class)
                .hasMessageContaining("Could not extract public key for the given private key.");
    }

    private String getResourceContent(String path) {
        try(InputStream resource = getResource(path);
            InputStreamReader inputStreamReader = new InputStreamReader(resource, StandardCharsets.UTF_8);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
            return bufferedReader.lines()
                    .collect(Collectors.joining(System.lineSeparator()));
        } catch (IOException e) {
           throw new UncheckedIOException(e);
        }
    }

    private InputStream getResource(String path) {
        return this.getClass().getClassLoader().getResourceAsStream(path);
    }

}
