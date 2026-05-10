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
package nl.altindag.ssl.pem.decryptor;

import nl.altindag.ssl.pem.util.PemUtils;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import static nl.altindag.laleler.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link PemUtils PemUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public final class Pkcs8Decryptor implements BouncyFunction<char[], InputDecryptorProvider> {

    private static final Pkcs8Decryptor INSTANCE = new Pkcs8Decryptor();
    private static final JceOpenSSLPKCS8DecryptorProviderBuilder PKCS8_DECRYPTOR_PROVIDER_BUILDER = new JceOpenSSLPKCS8DecryptorProviderBuilder();

    private Pkcs8Decryptor() {}

    @Override
    public InputDecryptorProvider apply(char[] password) throws OperatorCreationException {
        requireNotNull(password, "A password is mandatory with an encrypted key");
        return PKCS8_DECRYPTOR_PROVIDER_BUILDER.build(password);
    }

    public static BouncyFunction<char[], InputDecryptorProvider> getInstance() {
        return INSTANCE;
    }

}
