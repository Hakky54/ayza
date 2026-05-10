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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static nl.altindag.laleler.CollectorsUtils.toUnmodifiableList;

/**
 * @author Hakan Altindag
 */
final class LinuxCertificateUtils extends OSCertificateUtils {

    private static LinuxCertificateUtils INSTANCE;

    private static final String HOME_DIRECTORY = System.getProperty("user.home");
    private static final List<Path> LINUX_CERTIFICATE_PATHS = Stream.of(
                    "/etc/ssl/certs",
                    "/etc/pki/nssdb",
                    "/usr/local/share/ca-certificates",
                    "/usr/share/ca-certificates",
                    "/etc/pki/tls/certs/ca-bundle.crt",
                    "/etc/pki/ca-trust/source/anchors",
                    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                    HOME_DIRECTORY + "/.pki/nssdb")
            .map(Paths::get)
            .collect(Collectors.toList());

    private LinuxCertificateUtils() {
    }

    @Override
    List<KeyStore> getTrustStores() {
        List<Certificate> certificates = getCertificates();
        if (!certificates.isEmpty()) {
            KeyStore linuxTrustStore = KeyStoreUtils.createTrustStore(certificates);
            return Collections.singletonList(linuxTrustStore);
        }

        return Collections.emptyList();
    }

    List<Certificate> getCertificates() {
        return getCertificates(LINUX_CERTIFICATE_PATHS).stream()
                .distinct()
                .collect(toUnmodifiableList());
    }

    static LinuxCertificateUtils getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new LinuxCertificateUtils();
        }
        return INSTANCE;
    }

}
