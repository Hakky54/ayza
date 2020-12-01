package nl.altindag.ssl.util;

import nl.altindag.ssl.SSLFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public final class JettySslUtils {

    private JettySslUtils() {}

    /**
     * Creates a basic {@link SslContextFactory.Client Client SslContextFactory}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextFactory.Client}
     */
    public static SslContextFactory.Client forClient(SSLFactory sslFactory) {
        return createSslContextFactory(sslFactory, new SslContextFactory.Client());
    }

    /**
     * Creates a basic {@link SslContextFactory.Server Server SslContextFactory}
     * with the available properties from {@link SSLFactory}.
     *
     * The returned object can be enriched with additional configuration for your needs
     *
     * @param sslFactory {@link SSLFactory}
     * @return {@link SslContextFactory.Server}
     */
    public static SslContextFactory.Server forServer(SSLFactory sslFactory) {
        return createSslContextFactory(sslFactory, new SslContextFactory.Server());
    }

    private static <T extends SslContextFactory> T createSslContextFactory(SSLFactory sslFactory, T sslContextFactory) {
        sslContextFactory.setSslContext(sslFactory.getSslContext());
        sslContextFactory.setIncludeProtocols(sslFactory.getSslParameters().getProtocols());
        sslContextFactory.setIncludeCipherSuites(sslFactory.getSslParameters().getCipherSuites());
        sslContextFactory.setHostnameVerifier(sslFactory.getHostnameVerifier());

        return sslContextFactory;
    }

}
