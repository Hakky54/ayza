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

import java.security.KeyStore;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static nl.altindag.laleler.CollectorsUtils.toUnmodifiableList;

final class WindowsCertificateUtils extends OSCertificateUtils {

    private static WindowsCertificateUtils INSTANCE;

    @Override
    List<KeyStore> getTrustStores() {
        return Stream.of("Windows-ROOT", "Windows-ROOT-LOCALMACHINE", "Windows-ROOT-CURRENTUSER", "Windows-MY", "Windows-MY-CURRENTUSER", "Windows-MY-LOCALMACHINE")
                .map(keystoreType -> createKeyStoreIfAvailable(keystoreType, null))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(toUnmodifiableList());
    }

    static WindowsCertificateUtils getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new WindowsCertificateUtils();
        }
        return INSTANCE;
    }

}
