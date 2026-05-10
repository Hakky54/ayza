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


import nl.altindag.laleler.IOUtils;
import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class LinuxCertificateUtilsShould {

    private static final String ORIGINAL_OS_NAME = System.getProperty("os.name").toLowerCase();

    @Test
    void getInstance() {
        LinuxCertificateUtils instance = LinuxCertificateUtils.getInstance();
        assertThat(instance)
                .isNotNull()
                .hasSameHashCodeAs(LinuxCertificateUtils.getInstance());
    }

    @Test
    void getCertificate() {
        if (ORIGINAL_OS_NAME.contains("linux")) {
            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isNotEmpty();
        }
    }

    @Test
    void getTrustStores() {
        if (ORIGINAL_OS_NAME.contains("linux")) {
            List<KeyStore> trustStores = LinuxCertificateUtils.getInstance().getTrustStores();
            assertThat(trustStores).isNotEmpty();
        } else {
            InputStream inputStream = IOUtils.getResourceAsStream("pem/badssl-certificate.pem");
            String content = IOUtils.getContent(inputStream);
            List<Certificate> mockedCertificates = CertificateUtils.parsePemCertificate(content);

            LinuxCertificateUtils linuxCertificateUtils = spy(LinuxCertificateUtils.getInstance());
            when(linuxCertificateUtils.getCertificates(anyList())).thenReturn(mockedCertificates);
            List<KeyStore> trustStores = linuxCertificateUtils.getTrustStores();

            assertThat(trustStores).isNotEmpty();
        }
    }

    @Test
    void returnEmptyListOfTrustStoresWhenNoCertificatesAreAvailable() {
        LinuxCertificateUtils linuxCertificateUtils = spy(LinuxCertificateUtils.getInstance());
        when(linuxCertificateUtils.getCertificates(anyList())).thenReturn(Collections.emptyList());
        List<KeyStore> trustStores = linuxCertificateUtils.getTrustStores();

        assertThat(trustStores).isEmpty();
    }

    @Test
    void getCertificatesWhenFileExistAndIsARegularFile() {
        InputStream inputStream = IOUtils.getResourceAsStream("pem/badssl-certificate.pem");
        String content = IOUtils.getContent(inputStream);
        List<Certificate> mockedCertificates = CertificateUtils.parsePemCertificate(content);

        LinuxCertificateUtils linuxCertificateUtils = spy(LinuxCertificateUtils.class);
        when(linuxCertificateUtils.getCertificates()).thenReturn(mockedCertificates);

        try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getInstance".equals(method.getName())) {
                return linuxCertificateUtils;
            } else {
                return invocation.callRealMethod();
            }
        });
             MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                 Method method = invocation.getMethod();
                 if ("exists".equals(method.getName())) {
                     return true;
                 } else if ("isRegularFile".equals(method.getName())) {
                     return true;
                 } else {
                     return invocation.callRealMethod();
                 }
             })) {

            System.setProperty("os.name", "linux");

            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isNotEmpty();

            resetOsName();
        }
    }

    @Test
    void getCertificatesWhenFilesExistUnderADirectory() {
        InputStream inputStream = IOUtils.getResourceAsStream("pem/badssl-certificate.pem");
        String content = IOUtils.getContent(inputStream);
        List<Certificate> mockedCertificates = CertificateUtils.parsePemCertificate(content);

        LinuxCertificateUtils linuxCertificateUtils = spy(LinuxCertificateUtils.class);
        when(linuxCertificateUtils.getCertificates()).thenReturn(mockedCertificates);

        try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getInstance".equals(method.getName())) {
                return linuxCertificateUtils;
            } else {
                return invocation.callRealMethod();
            }
        });
             MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                 Method method = invocation.getMethod();
                 if ("exists".equals(method.getName())) {
                     return true;
                 } else if ("isRegularFile".equals(method.getName())) {
                     return true;
                 } else {
                     return invocation.callRealMethod();
                 }
             })) {

            System.setProperty("os.name", "linux");

            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isNotEmpty();

            resetOsName();
        }
    }

    @Test
    void getCertificatesReturnsEmptyListWhenFileDoesNotExist() {
        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            if ("exists".equals(method.getName())) {
                return false;
            } else if ("isRegularFile".equals(method.getName())) {
                return true;
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isEmpty();
        }
    }

    @Test
    void getCertificatesReturnsEmptyListWhenFileExistButIsNotARegularFile() {
        System.setProperty("os.name", "linux");

        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            String methodName = method.getName();
            if ("exists".equals(methodName)) {
                return true;
            } else if ("isRegularFile".equals(methodName)) {
                return false;
            } else if ("isDirectory".equals(methodName)) {
                return true;
            } else if ("walk".equals(methodName)) {
                return Stream.of(Paths.get("/etc/ssl/certs/some-certificate.pem"));
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isEmpty();
        }

        resetOsName();
    }

    @Test
    void getCertificatesReturnsEmptyListWhenFileExistButIsNotARegularFileAndAlsoNotADirectory() {
        System.setProperty("os.name", "linux");

        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            String methodName = method.getName();
            if ("exists".equals(methodName)) {
                return true;
            } else if ("isRegularFile".equals(methodName)) {
                return false;
            } else if ("isDirectory".equals(methodName)) {
                return false;
            } else if ("walk".equals(methodName)) {
                return Stream.of(Paths.get("/etc/ssl/certs/some-certificate.pem"));
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isEmpty();
        }

        resetOsName();
    }

    @Test
    void getCertificatesReturnsCertificatesWhenFileExistWithinDirectory() {
        System.setProperty("os.name", "linux");

        if (!ORIGINAL_OS_NAME.contains("windows")) {
            InputStream inputStream = IOUtils.getResourceAsStream("pem/badssl-certificate.pem");
            String content = IOUtils.getContent(inputStream);
            List<Certificate> mockedCertificates = CertificateUtils.parsePemCertificate(content);

            LinuxCertificateUtils linuxCertificateUtils = spy(LinuxCertificateUtils.class);
            when(linuxCertificateUtils.getCertificates()).thenReturn(mockedCertificates);

            try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class, invocation -> {
                Method method = invocation.getMethod();
                if ("getInstance".equals(method.getName())) {
                    return linuxCertificateUtils;
                } else {
                    return invocation.callRealMethod();
                }
            });
                 MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                     Method method = invocation.getMethod();
                     String methodName = method.getName();

                     if (invocation.getArguments().length == 0) {
                         return invocation.callRealMethod();
                     }

                     String path = invocation.getArguments()[0].toString();
                     if ("exists".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                         return true;
                     } else if ("isRegularFile".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                         return false;
                     } else if ("isSymbolicLink".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                         return false;
                     } else if ("isDirectory".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                         return true;
                     } else if ("walk".equals(methodName)) {
                         return Stream.of(Paths.get("/etc/ssl/certs/some-certificate.pem"));
                     } else if ("isRegularFile".equals(methodName) && "/etc/ssl/certs/some-certificate.pem".equals(path)) {
                         return true;
                     } else if ("isSymbolicLink".equals(methodName) && "/etc/ssl/certs/some-certificate.pem".equals(path)) {
                         return true;
                     } else if ("exists".equals(methodName)) {
                         return false;
                     } else {
                         return invocation.callRealMethod();
                     }
                 })) {

                List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
                assertThat(certificates).isNotEmpty();
            }
        }

        resetOsName();
    }

    @Test
    void wrapAnIOExceptionInAGenericIOExceptionWhenFilesWalkFails() {
        System.setProperty("os.name", "linux");

        if (!ORIGINAL_OS_NAME.contains("windows")) {
            try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                Method method = invocation.getMethod();
                String methodName = method.getName();

                if (invocation.getArguments().length == 0) {
                    return invocation.callRealMethod();
                }

                String path = invocation.getArguments()[0].toString();
                if ("exists".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                    return true;
                } else if ("isRegularFile".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                    return false;
                } else if ("isDirectory".equals(methodName) && "/etc/ssl/certs".equals(path)) {
                    return true;
                } else if ("walk".equals(methodName)) {
                    throw new IOException("KABOOM");
                } else {
                    return invocation.callRealMethod();
                }
            })) {

                assertThatThrownBy(() -> LinuxCertificateUtils.getInstance().getCertificates())
                        .isInstanceOf(GenericIOException.class)
                        .hasMessageContaining("KABOOM");
            }
        }

        resetOsName();
    }

    @Test
    void ignoreAnyErrorWhenCallingLoadCertificate() {
        try (MockedStatic<CertificateUtils> certificateUtilsMockedStatic = mockStatic(CertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadCertificate".equals(method.getName())) {
                throw new IOException("KABOOM");
            } else {
                return invocation.callRealMethod();
            }
        });
             MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                 Method method = invocation.getMethod();
                 if ("exists".equals(method.getName())) {
                     return true;
                 } else if ("isRegularFile".equals(method.getName())) {
                     return true;
                 } else {
                     return invocation.callRealMethod();
                 }
             })) {

            System.setProperty("os.name", "linux");

            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isEmpty();

            certificateUtilsMockedStatic.verify(() -> CertificateUtils.loadCertificate(any(Path.class)), times(8));

            resetOsName();
        }
    }

    @Test
    void notGetCertificatesIfPathIsNotARegularFileAndAlsoNotADirectory() {
        System.setProperty("os.name", "linux");

        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            String methodName = method.getName();

            if ("exists".equals(methodName)) {
                return false;
            } else if ("isRegularFile".equals(methodName)) {
                return false;
            } else if ("isDirectory".equals(methodName)) {
                return false;
            } else {
                return invocation.callRealMethod();
            }
        })) {

            List<Certificate> certificates = LinuxCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isEmpty();
        }

        resetOsName();
    }

    @Test
    void containAListOfToBeSearchPathsForCertificates() {
        System.setProperty("os.name", "linux");

        if (!ORIGINAL_OS_NAME.contains("windows")) {
            List<String> capturedPaths = new ArrayList<>();
            try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
                Method method = invocation.getMethod();
                if ("exists".equals(method.getName())) {
                    String absolutePath = invocation.getArguments()[0].toString();
                    capturedPaths.add(absolutePath);
                    return false;
                } else {
                    return invocation.callRealMethod();
                }
            })) {

                LinuxCertificateUtils.getInstance().getCertificates();
                assertThat(capturedPaths).containsExactly(
                        "/etc/ssl/certs",
                        "/etc/pki/nssdb",
                        "/usr/local/share/ca-certificates",
                        "/usr/share/ca-certificates",
                        "/etc/pki/tls/certs/ca-bundle.crt",
                        "/etc/pki/ca-trust/source/anchors",
                        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                        System.getProperty("user.home") + "/.pki/nssdb"
                );
            }
        }

        resetOsName();
    }

    private void resetOsName() {
        System.setProperty("os.name", ORIGINAL_OS_NAME);
    }

}
