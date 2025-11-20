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
package nl.altindag.ssl.provider;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.socket.FenixSSLSocketFactory;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class FenixProviderShould {

    @Test
    void haveDefaultProperties() {
        FenixProvider provider = new FenixProvider();
        Map<Object, Object> properties = provider.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        assertThat(properties).containsOnly(
                new SimpleEntry<>("Alg.Alias.SSLContext.SSL", "TLS"),
                new SimpleEntry<>("Alg.Alias.SSLContext.SSLv2", "TLS"),
                new SimpleEntry<>("Alg.Alias.SSLContext.SSLv3", "TLS"),
                new SimpleEntry<>("Alg.Alias.SSLContext.TLSv1", "TLS"),
                new SimpleEntry<>("Alg.Alias.SSLContext.TLSv1.1", "TLS"),
                new SimpleEntry<>("Alg.Alias.SSLContext.TLSv1.2", "TLS"),
                new SimpleEntry<>("Alg.Alias.SSLContext.TLSv1.3", "TLS"),
                new SimpleEntry<>("Alg.Alias.SSLContext.Default", "TLS"),
                new SimpleEntry<>("Provider.id className", "nl.altindag.ssl.provider.FenixProvider"),
                new SimpleEntry<>("Provider.id info", "Fenix Security Provider"),
                new SimpleEntry<>("Provider.id name", "Fenix"),
                new SimpleEntry<>("Provider.id version", "1.0"),
                new SimpleEntry<>("SSLContext.TLS", "nl.altindag.ssl.sslcontext.FenixSSLContextSpi")
        );
    }

    @Test
    void returnSslContextOriginatedFromTheConfiguredSslContextForTheConfiguredProtocols() throws NoSuchAlgorithmException {
        try {
            SSLFactory mockedSslFactory = mock(SSLFactory.class);
            SSLContext mockedSslContext = mock(SSLContext.class);
            SSLSocketFactory mockedSslSocketFactory = mock(SSLSocketFactory.class);
            SSLParameters mockedSslParameters = mock(SSLParameters.class);

            when(mockedSslFactory.getSslContext()).thenReturn(mockedSslContext);
            when(mockedSslFactory.getSslParameters()).thenReturn(mockedSslParameters);
            when(mockedSslContext.getSocketFactory()).thenReturn(mockedSslSocketFactory);

            SSLFactoryProvider.set(mockedSslFactory);
            FenixProvider provider = new FenixProvider();
            Security.insertProviderAt(provider, 1);

            for (String protocol : Arrays.asList("Default", "SSL", "SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "TLS")) {
                SSLContext sslContext = SSLContext.getInstance(protocol);
                assertThat(sslContext.getProvider()).isEqualTo(provider);
                assertThat(sslContext.getSocketFactory()).isInstanceOf(FenixSSLSocketFactory.class);
            }
        } finally {
            Security.removeProvider("Fenix");
            SSLFactoryProvider.set(null);
        }
    }

}
