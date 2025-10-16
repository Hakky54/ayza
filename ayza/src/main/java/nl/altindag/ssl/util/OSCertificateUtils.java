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

import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.KeyStoreUtils.countAmountOfTrustMaterial;
import static nl.altindag.ssl.util.KeyStoreUtils.createKeyStore;

abstract class OSCertificateUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(OSCertificateUtils.class);

    abstract List<KeyStore> getTrustStores();

    List<Certificate> getCertificates(List<Path> certificatePaths) {
        List<Certificate> certificates = new ArrayList<>();
        try {
            for (Path path : certificatePaths) {
                if (Files.exists(path)) {
                    if (Files.isRegularFile(path)) {
                        List<Certificate> certs = loadCertificate(path);
                        certificates.addAll(certs);
                    } else if (Files.isDirectory(path)) {
                        try(Stream<Path> files = Files.walk(path, 1, FileVisitOption.FOLLOW_LINKS)) {
                            List<Certificate> certs = files
                                    .filter(Files::isRegularFile)
                                    .flatMap(file -> loadCertificate(file).stream())
                                    .collect(Collectors.toList());
                            certificates.addAll(certs);
                        }
                    }
                }
            }
            return Collections.unmodifiableList(certificates);
        } catch (IOException e) {
            throw new GenericIOException(e);
        }
    }

    List<Certificate> loadCertificate(Path path) {
        try {
            return CertificateUtils.loadCertificate(path);
        } catch (Exception e) {
            // Ignore exception and skip trying to parse the file as it is most likely
            // not a (supported) certificate at all. It might be a regular text file maybe containing random text?
            return Collections.emptyList();
        }
    }

    List<Path> findPathsWithSamePrefix(String filenamePrefix, Path rootPath) {
        try (Stream<Path> files = Files.list(rootPath)) {
            return files.filter(Files::isDirectory)
                    .filter(path -> path.getFileName().toString().startsWith(filenamePrefix))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    @SuppressWarnings("SameParameterValue")
    Optional<KeyStore> createKeyStoreIfAvailable(String keyStoreType, char[] keyStorePassword) {
        try {
            KeyStore keyStore = createKeyStore(keyStoreType, keyStorePassword);

            if (LOGGER.isDebugEnabled()) {
                int totalTrustedCertificates = countAmountOfTrustMaterial(keyStore);
                LOGGER.debug(String.format("Successfully loaded KeyStore of the type [%s] having [%d] entries", keyStoreType, totalTrustedCertificates));
            }
            return Optional.of(keyStore);
        } catch (Exception ignored) {
            LOGGER.debug(String.format("Failed to load KeyStore of the type [%s]", keyStoreType));
            return Optional.empty();
        }
    }

}
