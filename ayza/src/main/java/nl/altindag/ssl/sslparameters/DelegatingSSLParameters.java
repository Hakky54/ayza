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
package nl.altindag.ssl.sslparameters;

import javax.net.ssl.SSLParameters;
import java.security.AlgorithmConstraints;

public class DelegatingSSLParameters extends SSLParameters {

    SSLParameters sslParameters;

    public DelegatingSSLParameters(SSLParameters sslParameters) {
        this.sslParameters = sslParameters;
        // the setter and getters are final for some methods and therefor are not set in the inner SSLParameters but delegated to the properties of the super class
        this.setUseCipherSuitesOrder(sslParameters.getUseCipherSuitesOrder());
    }

    public SSLParameters getInnerSslParameters() {
        return sslParameters;
    }

    @Override
    public String[] getCipherSuites() {
        return sslParameters.getCipherSuites();
    }

    @Override
    public String[] getProtocols() {
        return sslParameters.getProtocols();
    }

    @Override
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public AlgorithmConstraints getAlgorithmConstraints() {
        return sslParameters.getAlgorithmConstraints();
    }

    @Override
    public String getEndpointIdentificationAlgorithm() {
        return sslParameters.getEndpointIdentificationAlgorithm();
    }

    @Override
    public void setCipherSuites(String[] cipherSuites) {
        sslParameters.setCipherSuites(cipherSuites);
    }

    @Override
    public void setProtocols(String[] protocols) {
        sslParameters.setProtocols(protocols);
    }

    @Override
    public void setWantClientAuth(boolean wantClientAuth) {
        sslParameters.setWantClientAuth(wantClientAuth);
    }

    @Override
    public void setNeedClientAuth(boolean needClientAuth) {
        sslParameters.setNeedClientAuth(needClientAuth);
    }

    @Override
    public void setAlgorithmConstraints(AlgorithmConstraints constraints) {
        sslParameters.setAlgorithmConstraints(constraints);
    }

    @Override
    public void setEndpointIdentificationAlgorithm(String algorithm) {
        sslParameters.setEndpointIdentificationAlgorithm(algorithm);
    }

    public void setSslParameters(SSLParameters sslParameters) {
        this.sslParameters = sslParameters;
    }

}
