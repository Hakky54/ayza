/*
 * Copyright 2019-2021 the original author or authors.
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

package nl.altindag.ssl.model;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <p>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * </p>
 *
 * @author Hakan Altindag
 */
public final class TrustMaterial {

    private X509ExtendedTrustManager trustManager;
    private TrustManagerFactory trustManagerFactory;
    private List<X509Certificate> trustedCertificates;
    private List<KeyStoreHolder> trustStores;

    private TrustMaterial() {}

    public X509ExtendedTrustManager getTrustManager() {
        return trustManager;
    }

    public TrustManagerFactory getTrustManagerFactory() {
        return trustManagerFactory;
    }

    public List<X509Certificate> getTrustedCertificates() {
        return trustedCertificates;
    }

    public List<KeyStoreHolder> getTrustStores() {
        return trustStores;
    }

    public static class Builder {

        private X509ExtendedTrustManager trustManager;
        private TrustManagerFactory trustManagerFactory;
        private List<X509Certificate> trustedCertificates;
        private List<KeyStoreHolder> trustStores;

        public Builder withTrustManager(X509ExtendedTrustManager trustManager) {
            this.trustManager = trustManager;
            return this;
        }

        public Builder withTrustManagerFactory(TrustManagerFactory trustManagerFactory) {
            this.trustManagerFactory = trustManagerFactory;
            return this;
        }

        public Builder withTrustedCertificates(List<X509Certificate> trustedCertificates) {
            this.trustedCertificates = trustedCertificates;
            return this;
        }

        public Builder withTrustStores(List<KeyStoreHolder> trustStores) {
            this.trustStores = trustStores;
            return this;
        }

        public TrustMaterial build() {
            TrustMaterial trustMaterial = new TrustMaterial();
            trustMaterial.trustManager = trustManager;
            trustMaterial.trustManagerFactory = trustManagerFactory;
            trustMaterial.trustedCertificates = trustedCertificates;
            trustMaterial.trustStores = trustStores;
            return trustMaterial;
        }
    }

}
