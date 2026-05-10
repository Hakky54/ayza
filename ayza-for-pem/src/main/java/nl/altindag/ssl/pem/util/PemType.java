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

import nl.altindag.ssl.pem.exception.PemParseException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.X509TrustedCertificateBlock;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.util.List;

import static nl.altindag.laleler.CollectionUtils.toUnmodifiableList;

enum PemType {

    CERTIFICATE(X509CertificateHolder.class, X509TrustedCertificateBlock.class),
    KEY(PrivateKeyInfo.class, PKCS8EncryptedPrivateKeyInfo.class, PEMKeyPair.class, PEMEncryptedKeyPair.class);

    private final List<Class<?>> supportedTypes;

    PemType(Class<?>... classes) {
        this.supportedTypes = toUnmodifiableList(classes);
    }

    static PemType from(Object object) {
        for (PemType pemType : values()) {
            for (Class<?> supportedType : pemType.supportedTypes) {
                if (supportedType.isInstance(object)) {
                    return pemType;
                }
            }
        }

        throw new PemParseException(String.format("The provided [%s] pem type is not (yet) supported", object.getClass().getName()));
    }

}
