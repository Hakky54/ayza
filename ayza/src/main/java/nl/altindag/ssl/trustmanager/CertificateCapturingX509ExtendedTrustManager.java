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
package nl.altindag.ssl.trustmanager;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public class CertificateCapturingX509ExtendedTrustManager extends DelegatingX509ExtendedTrustManager {

    private static final Function<X509Certificate[], List<X509Certificate>> COLLECTION_MAPPER = chain -> new ArrayList<>(Arrays.asList(chain));
    private static final BiFunction<List<X509Certificate>, X509Certificate[], List<X509Certificate>> COLLECTION_MERGER = (list, array) -> {
        List<X509Certificate> result = new ArrayList<>(list);
        result.addAll(list);
        result.addAll(Arrays.asList(array));
        return result;
    };

    private final Map<String, List<X509Certificate>> certificatesCollector;

    public CertificateCapturingX509ExtendedTrustManager(X509ExtendedTrustManager trustManager, Map<String, List<X509Certificate>> certificatesCollector) {
        super(trustManager);
        this.certificatesCollector = certificatesCollector;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        certificatesCollector.compute("no-host", (k, v) -> v == null ? COLLECTION_MAPPER.apply(chain) : COLLECTION_MERGER.apply(v, chain));
        super.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        certificatesCollector.compute("no-host", (k, v) -> v == null ? COLLECTION_MAPPER.apply(chain) : COLLECTION_MERGER.apply(v, chain));
        super.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        certificatesCollector.put(((InetSocketAddress) socket.getRemoteSocketAddress()).getHostName(), COLLECTION_MAPPER.apply(chain));
        super.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        certificatesCollector.put(sslEngine.getPeerHost(), COLLECTION_MAPPER.apply(chain));
        super.checkClientTrusted(chain, authType, sslEngine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        certificatesCollector.put(((InetSocketAddress) socket.getRemoteSocketAddress()).getHostName(), COLLECTION_MAPPER.apply(chain));
        super.checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        certificatesCollector.put(sslEngine.getPeerHost(), COLLECTION_MAPPER.apply(chain));
        super.checkServerTrusted(chain, authType, sslEngine);
    }

}
