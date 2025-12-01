[![Actions Status](https://github.com/Hakky54/ayza/workflows/Build/badge.svg)](https://github.com/Hakky54/ayza/actions)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Aayza-parent&metric=security_rating)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Aayza-parent)
[![Known Vulnerabilities](https://snyk.io/test/github/Hakky54/ayza/badge.svg)](https://snyk.io/test/github/Hakky54/ayza)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Aayza-parent&metric=coverage)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Aayza-parent)
[![JDK Compatibility](https://img.shields.io/badge/JDK_Compatibility-8+-blue.svg)](#)
[![Kotlin Compatibility](https://img.shields.io/badge/Kotlin_Compatibility-1.5+-blue.svg)](#)
[![Scala Compatibility](https://img.shields.io/badge/Scala_Compatibility-2.11+-blue.svg)](#)
[![Android API Compatibility](https://img.shields.io/badge/Android_API_Compatibility-24+-blue.svg)](#)
[![Apache2 license](https://img.shields.io/badge/license-Aache2.0-blue.svg)](https://github.com/Hakky54/ayza/blob/master/LICENSE)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.hakky54/ayza/badge.svg)](https://mvnrepository.com/artifact/io.github.hakky54/ayza)
[![Dependencies: none](https://img.shields.io/badge/dependencies-1-blue.svg)](#)
[![GitHub stars chart](https://img.shields.io/badge/github%20stars-chart-blue.svg)](https://seladb.github.io/StarTrack-js/#/preload?r=hakky54,ayza)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FHakky54%2Fayza.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FHakky54%2Fayza?ref=badge_shield)

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Aayza-parent)

# Ayza 🔐
Hey, hello there 👋 Welcome, I hope you will like this library. Feel free to drop a message in the [📖 Guestbook](https://github.com/Hakky54/ayza/discussions/302), I would love to hear your story and experience in using this library.

I have created this library with ❤️ and passion, mostly during evening and night hours. If you use my library and want to appreciate the work I have done, please consider to sponsor this project as a way to contribute back to the community.
There are 3 options available to pick from: [GitHub](https://github.com/sponsors/Hakky54), [Ko-fi](https://ko-fi.com/hakky54) and [Open Collective](https://opencollective.com/hakky54)

# Install library with:
### Install with [Maven](https://mvnrepository.com/artifact/io.github.hakky54/ayza)
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>ayza</artifactId>
    <version>10.0.2</version>
</dependency>
```
### Install with Gradle
```groovy
implementation 'io.github.hakky54:ayza:10.0.2'
```
### Install with Gradle Kotlin DSL
```kotlin
implementation("io.github.hakky54:ayza:10.0.2")
```
### Install with Scala SBT
```
libraryDependencies += "io.github.hakky54" % "ayza" % "10.0.2"
```
### Install with Apache Ivy
```xml
<dependency org="io.github.hakky54" name="ayza" rev="10.0.2"/>
```

## Table of contents
1. [Introduction](#introduction)
   - [History](#history)
   - [Advantages](#advantages)
   - [Definitions](#definitions)
   - [Compatibility](#compatibility)
2. [Usage](#usage)
   - [Example configuration](#basic-example-configuration)
   - [Other possible configurations](#other-possible-configurations)
     - [Loading keystore from the classpath](#loading-keystore-and-truststore-from-the-classpath)
     - [Loading keystore from the file system](#loading-keystore-and-trust-store-from-anywhere-on-the-filesystem)
     - [Loading keystore from InputStream](#loading-keystore-and-trust-store-from-inputstream)
     - [Loading trust material with OCSP options](#loading-trust-material-with-ocsp-options)
         - [TrustStore from the classpath](#loading-trust-material-with-truststore-and-ocsp-options-from-the-classpath)
         - [TrustStore from the file system](#loading-trust-material-with-truststore-and-ocsp-options-from-the-file-system)
         - [TrustManager](#loading-trust-material-with-trustmanager-and-ocsp-options)
         - [Certificates](#loading-trust-material-with-certificates-and-ocsp-options)
     - [Enhanceable trust validations](#enhanceable-trust-validations)
     - [Hide trusted certificate names of a server](#hide-trusted-certificate-names-of-a-server)
     - [Skip certificate validation](#trusting-all-certificates-without-validation-not-recommended-to-use-at-production)
     - [Skip hostname validation](#skip-hostname-validation)
     - [Loading JDK and OS trusted certificates](#loading-jdk-and-os-trusted-certificates)
     - [Using specific protocols and ciphers with custom secure-random and hostname-verifier](#using-specific-protocols-ciphers-with-custom-secure-random-and-hostname-verifier)
     - [Enhanceable hostname verifier](#enhanceable-hostname-verifier)
     - [Using multiple identity materials and trust materials](#support-for-using-multiple-identity-materials-and-trust-materials)
     - [Using custom KeyManager and TrustManager](#support-for-using-x509extendedkeymanager-and-x509extendedtrustmanager)
     - [Using dummy identity and trust material](#using-dummy-identity-and-trust-material)
     - [Using KeyStore with multiple keys having different passwords](#support-for-using-a-single-keystore-which-contains-multiple-keys-with-different-passwords)
     - [Using custom PrivateKey and Certificates](#support-for-using-privatekey-and-certificates)
     - [Reloading SSL at runtime](#support-for-reloading-ssl-at-runtime)
     - [Hot swap KeyManager and TrustManager at runtime](#support-for-swapping-keymanager-and-trustmanager-at-runtime)
     - [Trust additional new certificates at runtime](#trust-additional-new-certificates-at-runtime)
     - [Routing client identity to specific host](#routing-identity-material-to-specific-host)
     - [Updating client identity routes at runtime](#updating-identity-routes-at-runtime) 
     - [Managing additional identities at runtime](#managing-additional-identities-at-runtime)
     - [Managing ssl session](#managing-ssl-session)
     - [Extracting server certificates](#extracting-server-certificates)
       - [Single server](#single-server)
       - [Bulk extraction from multiple servers](#bulk-extraction-from-multiple-servers)
       - [Extracting certificates behind proxy](#extracting-certificates-behind-proxy)
       - [Extracting certificates behind proxy with authentication](#extracting-certificates-behind-proxy-with-authentication)
       - [Extracting certificates as pem](#extracting-certificates-as-pem)
     - [Using P7B or PKCS#7 files](#using-p7b-or-pkcs7-files)
     - [Using DER files](#using-der-files)
     - [Using PFX or P12 or PKCS#12 Files](#using-pfx-p12-or-pkcs12-files)
     - [Using PEM Files](#using-pem-files)
       - [Loading pem files from the classpath](#loading-pem-files-from-the-classpath)
       - [Loading pem files from the file system](#loading-pem-files-from-anywhere-on-the-filesystem)
       - [Loading pem files from InputStream](#loading-pem-files-from-inputstream)
       - [Loading pem files from string content](#loading-pem-files-from-string-content)
       - [Loading encrypted pem files](#loading-encrypted-pem-files)
     - [Migrating from classic configuration](#migrating-from-classic-configuration)
     - [Global SSL configuration](#global-ssl-configuration)
     - [Logging certificate validation](#logging-detailed-certificate-validation)
     - [Logging detailed KeyManager flow, input and output](#logging-detailed-keymanager-flow-input-and-output)
     - [Fluently mapping SSLFactory](#fluently-mapping-sslfactory)
   - [Returnable values from the SSLFactory](#returnable-values-from-the-sslfactory)
3. [Additional mappers for specific libraries](#additional-mappers-for-specific-libraries)
   - [Netty](#netty)
   - [Jetty](#jetty)
   - [Apache](#apache)
     - [Apache 4](#apache-4)
     - [Apache 5](#apache-5)
4. [Tested HTTP Clients](#tested-http-clients)
5. [Contributing](#contributing)
6. [Contributors](#contributors-)   
7. [License](#license)

## Introduction
Ayza is a library which provides a High-Level SSLFactory class for configuring a http client or a server to communicate over SSL/TLS for one way authentication or two-way authentication.
It is designed to be as lightweight as possible by having minimized the external dependencies. The core library only depends on the SLF4J logging API.

### History
As a Java developer I worked for different kinds of clients. Most of the time the application required to call other microservices within the organization or some other http servers. 
These requests needed to be secured, and therefore it was required to load the ssl materials into the http client. Each http client may require different input value to enable https requests, and therefore I couldn't just copy-paste my earlier configuration into the new project. 
The resulting configuration was in my opinion always verbose, not reusable, hard to test and hard to maintain. 

As a developer you also need to know how to properly load your file into your application and consume it as a KeyStore instance. Therefore, you also need to understand how to properly create for example a KeyManager and a TrustManager for you SSLContext. 
Ayza is taking the responsibility of creating an instance of SSLContext from the provided arguments, and it will provide you all the ssl materials which are required to configure [40+ different Http Client](#tested-http-clients) for Java, Scala and Kotlin. 
I wanted the library to be as easy as possible to use for all developers to give them a kickstart when configuring their Http Client. So feel free to provide feedback or feature requests. 

The library has been renamed to Ayza in September 2025 as I wanted a shorter name, which is easy to pronounce and to make it easy to remember. Detailed information about the rename can be found here: [Renaming project to Ayza](https://github.com/Hakky54/ayza/discussions/670)

The library by the way also provides other utilities such as:
- [CertificateExtractingClient](ayza/src/main/java/nl/altindag/ssl/util/CertificateExtractingClient.java)
- [CertificateUtils](ayza/src/main/java/nl/altindag/ssl/util/CertificateUtils.java)
- [HostnameVerifierUtils](ayza/src/main/java/nl/altindag/ssl/util/HostnameVerifierUtils.java)
- [KeyStoreUtils](ayza/src/main/java/nl/altindag/ssl/util/KeyStoreUtils.java)
- [KeyManagerUtils](ayza/src/main/java/nl/altindag/ssl/util/KeyManagerUtils.java)
- [TrustManagerUtils](ayza/src/main/java/nl/altindag/ssl/util/TrustManagerUtils.java)
- [PemUtils](ayza-for-pem/src/main/java/nl/altindag/ssl/pem/util/PemUtils.java)
- [ProviderUtils](ayza/src/main/java/nl/altindag/ssl/util/ProviderUtils.java)
- [SSLContextUtils](ayza/src/main/java/nl/altindag/ssl/util/SSLContextUtils.java)
- [SSLFactoryUtils](ayza/src/main/java/nl/altindag/ssl/util/SSLFactoryUtils.java)
- [SSLParametersUtils](ayza/src/main/java/nl/altindag/ssl/util/SSLParametersUtils.java)
- [SSLSessionUtils](ayza/src/main/java/nl/altindag/ssl/util/SSLSessionUtils.java)
- [SSLSocketUtils](ayza/src/main/java/nl/altindag/ssl/util/SSLSocketUtils.java)

### Advantages:
* No need for low-level SSLContext configuration anymore
* No knowledge needed about SSLContext, TrustManager, TrustManagerFactory, KeyManager, KeyManagerFactory and how to create it.
* Above classes will all be created with just providing an identity and a trust material
* Load multiple identities/trustStores/keyManagers/trustManagers
* Hot reload ssl material without need of restarting/recreating Http Client or Server

### Definitions
* Identity material: A KeyStore or KeyManager which holds the key pair also known as private and public key
* Trust material: A KeyStore or TrustManager containing one or more certificates also known as public key. This KeyStore contains a list of trusted certificates
* One way authentication (also known as one way tls, one way ssl): Https connection where the client validates the certificate of the counter party
* Two way authentication (also known as two way tls, two way ssl, mutual authentication): Https connection where the client as well as the counter party validates the certificate, also known as mutual authentication

### Compatibility

|    Java     |    Kotlin     | Scala | Android |
|:-----------:|:-------------:|:-----:|:-------:|
|     8+      |     1.5+      | 2.11+ |   24+   |

## Usage
### Basic example configuration
Example configuration with apache http client, or [click here to view the other client configurations](#tested-http-clients)
```java
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import nl.altindag.ssl.SSLFactory;

public class App {

    public static void main(String[] args) throws IOException, JSONException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslFactory.getSslContext())
                .setSSLHostnameVerifier(sslFactory.getHostnameVerifier())
                .build();

        HttpGet request = new HttpGet("https://api.chucknorris.io/jokes/random");

        HttpResponse response = httpClient.execute(request);
        String chuckNorrisJoke = new JSONObject(EntityUtils.toString(response.getEntity())).getString("value");

        System.out.println(String.format("Received the following status code: %d", response.getStatusLine().getStatusCode()));
        System.out.println(String.format("Received the following joke: %s", chuckNorrisJoke));
    }

}
```
Response:
```text
Received the following status code: 200
Received the following joke: If a black cat crosses your path, you have bad luck. If Chuck Norris crosses your path, it was nice knowing you.
```

#### Other possible configurations
##### Loading keystore and truststore from the classpath
```text
SSLFactory.builder()
          .withIdentityMaterial("identity.jks", "password".toCharArray())
          .withTrustMaterial("truststore.jks", "password".toCharArray())
          .build();
```

##### Loading keystore and trust store from anywhere on the filesystem
```text
SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
```

##### Loading keystore and trust store from InputStream
```text
InputStream keyStoreStream = ...
InputStream trustStoreStream = ...

SSLFactory.builder()
          .withIdentityMaterial(keyStoreStream, "password".toCharArray())
          .withTrustMaterial(trustStoreStream, "password".toCharArray())
          .build();
```

##### Loading trust material with OCSP options
##### Loading trust material with TrustStore and OCSP options from the classpath
```text
CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial("truststore.jks", "password".toCharArray(), trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```
##### Loading trust material with TrustStore and OCSP options from the file system
```text
CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray(), trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```
##### Loading trust material with TrustManager and OCSP options
```text
X509ExtendedTrustManager trustManager = ...

CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial(trustManager, trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```

##### Loading trust material with certificates and OCSP options
```text
List<Certificate> certificates = ...

CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial(certificates, trustStore -> {
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            pkixBuilderParameters.addCertPathChecker(revocationChecker);
            return new CertPathTrustManagerParameters(pkixBuilderParameters);
        })
        .build();
```

##### Enhanceable trust validations
By default, the TrustManager ships with default validations to validate if the counterparty is trusted during the SSL Handshake. 
If needed the default behaviour can be overruled by custom validators.
If a custom validator is specified and if the condition evaluates to true, then the certificate of the counterparty will be trusted. If the condition evaluates to false, than it will fall back to the default behaviour of the TrustManager.
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withTrustEnhancer(trustManagerParameters -> {
              X509Certificate[] chain = trustManagerParameters.getChain();
              return chain[0].getIssuerX500Principal().getName().equals("Foo")
                      && chain[0].getSubjectX500Principal().getName().equals("Bar");
          })
          .build();
```
##### Hide trusted certificate names of a server
By default, a server exposes the list of trusted certificate names if requested by the client. The list of trusted certificate names can be requested with:
```shell
openssl s_client -showcerts -servername 127.0.0.1 -connect 127.0.0.1:8443
```

The output will be under `Acceptable client certificate CA names`:
![alt text](https://github.com/Hakky54/ayza/blob/master/images/demo-sending-server-ca-names.png?raw=true)

For some end-user this might lead into information leaks and security risks. This information can be hidden away so the client cannot request it anymore with an additional option within the `SSLFactory#withConcealedTrustMaterial()`. An example usage would be:
```text
SSLFactory updatedSslFactory = SSLFactory.builder()
      .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
      .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
      .withConcealedTrustMaterial()
      .build();
```

Which will result into the following output:
![alt text](https://github.com/Hakky54/ayza/blob/master/images/demo-not-sending-server-ca-names.png?raw=true)

##### Trusting all certificates without validation, not recommended to use at production!
```text
SSLFactory.builder()
          .withUnsafeTrustMaterial()
          .build();
```

##### Skip hostname validation
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withUnsafeHostnameVerifier()
          .build();

HttpsURLConnection.setDefaultHostnameVerifier(sslFactory.getHostnameVerifier());
System.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
```

##### Loading JDK and OS trusted certificates
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withSystemTrustMaterial()
          .build();
```

##### Using specific protocols, ciphers with custom secure random and hostname verifier
If you are using java 11 or newer, than you are also able to use TLSv1.3 as encryption protocol by default.
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withProtocols("TLSv1.3", "TLSv1.2")
          .withCiphers("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")
          .withHostnameVerifier(hostnameVerifier)
          .withSecureRandom(secureRandom)
          .build();
```

### Enhanceable hostname verifier
If you want to improve or whitelist certain hostnames from the default hostname verifier, you can apply the snippet bellow. If the method body returns true the hostname will be trusted by default
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withHostnameVerifierEnhancer(parameters -> "localhost".equals(parameters.getHostname()))
          .build();
```

##### Support for using multiple identity materials and trust materials
```text
SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withIdentityMaterial("identity-3.jks", password)
          .withIdentityMaterial("identity-4.jks", password)
          .withTrustMaterial("truststore-1.jks", password)
          .withTrustMaterial("truststore-2.jks", password)
          .withTrustMaterial("truststore-3.jks", password)
          .withTrustMaterial("truststore-4.jks", password)
          .build();
```
In some use cases multiple identities can fail to work. If that happens please try to add the additional SSLFactory option of identity route. See here for more: [Routing identity to specific host](#routing-identity-material-to-specific-host)

##### Support for using X509ExtendedKeyManager and X509ExtendedTrustManager
```text
X509ExtendedKeyManager keyManager = ...
X509ExtendedTrustManager trustManager = ...

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustMaterial(trustManager)
          .build();
```

##### Using dummy identity and trust material
In some use cases it may be useful to use a dummy identity or trust material. An example use case would be to create a base SSLFactory with the dummies which can be swapped afterwords. See below for a refactored version of [Support for swapping KeyManager and TrustManager at runtime](#support-for-swapping-keymanager-and-trustmanager-at-runtime).
```text
SSLFactory baseSslFactory = SSLFactory.builder()
          .withDummyIdentityMaterial()
          .withDummyTrustMaterial()
          .withSwappableIdentityMaterial()
          .withSwappableTrustMaterial()
          .build();
          
HttpClient httpClient = HttpClient.newBuilder()
          .sslParameters(sslFactory.getSslParameters())
          .sslContext(sslFactory.getSslContext())
          .build()
          
Runnable sslUpdater = () -> {
    SSLFactory updatedSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
    
    SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);
};

// initial update of ssl material to replace the dummies
sslUpdater.run();
   
// update ssl material every hour    
Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(sslUpdater, 1, 1, TimeUnit.HOURS);

HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());
```
##### Support for using a single KeyStore which contains multiple keys with different passwords
```text
KeyStore keyStore = ...
X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(keyStore, Map.of(
        "foo","foo-password".toCharArray(),
        "bar","bar-password".toCharArray(),
        "lorum-ipsum","lorum-ipsum-password".toCharArray()
));

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withDefaultTrustMaterial()
          .build();
```
##### Support for using PrivateKey and Certificates
```text
PrivateKey privateKey = ...
char[] privateKeyPassword = ...
Certificate[] certificateChain = ...

Certificate trustedCertificate = ...

SSLFactory.builder()
          .withIdentityMaterial(privateKey, privateKeyPassword, certificateChain)
          .withTrustMaterial(trustedCertificate)
          .build();
```
##### Support for reloading ssl at runtime
###### Reload identity and trust material
It is possible to reload or update the ssl configuration while already using it with your client or server without the need of restarting your application or recreating it with SSLFactory. The identity and trust material may expire at some point in time and needs to be replaced to be still functional.
Restart of the application with a traditional setup is unavoidable and can result into a downtime for x amount of time. A restart is not needed when using the setup below. The below example is a high-level method of reloading the ssl configuration, if you prefer to use a low-level setup please have a look at the following example displayed here: [Hot swap KeyManager and TrustManager at runtime](#support-for-swapping-keymanager-and-trustmanager-at-runtime).
```text
SSLFactory baseSslFactory = SSLFactory.builder()
          .withDummyIdentityMaterial()
          .withDummyTrustMaterial()
          .withSwappableIdentityMaterial()
          .withSwappableTrustMaterial()
          .build();
          
HttpClient httpClient = HttpClient.newBuilder()
          .sslParameters(sslFactory.getSslParameters())
          .sslContext(sslFactory.getSslContext())
          .build()
          
Runnable sslUpdater = () -> {
    SSLFactory updatedSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
    
    SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);
};

// initial update of ssl material to replace the dummies
sslUpdater.run();
   
// update ssl material every hour    
Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(sslUpdater, 1, 1, TimeUnit.HOURS);

HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());
```
See here for a basic reference implementation for a server: [GitHub - Instant SSL Reloading](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading)
The code example above cleans the cache instantly which forces any client or server to create a new ssl session and so it requires a new ssl handshake. If you prefer to use existing ssl session for existing connection, but want to use a new ssl session for new clients or servers, then you can use the following snippet below. 
In that way existing connections which already have done the ssl handshake won't require to do another handshake till the ssl session expires with the default timeout. 
```text
SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory, false);
```

See also here for other examples:
- [Instant Server SSL Reloading with Spring Boot and Jetty](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading)
- [Instant Server SSL Reloading with Spring Boot and Tomcat](https://github.com/Hakky54/java-tutorials/tree/main/instant-ssl-reloading-with-spring-tomcat)
- [Instant Server SSL Reloading with Vert.x](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading-with-vertx/vertx-server)
- [Instant Server SSL Reloading with Netty](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading-with-netty/netty-server)
- [Instant Server SSL Reloading with gRPC](https://github.com/Hakky54/java-tutorials/tree/main/grpc-client-server-with-ssl/instant-server-ssl-reloading-with-grpc)
- [Instant Server SSL Reloading with Spring Boot and Jetty and Database](https://github.com/Hakky54/java-tutorials/tree/main/instant-ssl-reloading-with-spring-jetty-database)
- [Instant Server SSL Reloading with Quarkus](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading-with-quarkus)

###### Reload ssl parameters
Additionally the SSL parameters can also be reloaded such as ciphers. A basic example is demonstrated below:
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .withSwappableSslParameters()
          .build();
          
sslFactory.getSslParameters().setCipherSuites(new String[]{"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"})
```
Please note that this might not work for all http clients and servers. It works out of the box with Jetty, but for Netty it needs some additional configuration see the code snippet below. It basically depends on how the http client or server uses the ciphers or other ssl properties during the ssl handshake.
Please be aware that this option has some limitations/drawbacks. It might cause other options of a server not to work, so it is advised to test this option in dept. If it breaks your server configuration such as ALPN I would not recommend to use reloadable ssl parameters. Updating your server properties and running a rolling update/restarting your server would be a better option.

The option below might be needed for some servers/clients to reload ssl parameters, for example Netty Server.
```text
SSLFactory sslFactory = ... // your initialized SSLFactory similar to the above one with SwappableSslParameters 
Provider provider = ProviderUtils.create(sslFactory);
Security.insertProviderAt(provider, 1);

// Initialize your server at this point
```

##### Support for swapping KeyManager and TrustManager at runtime
It is possible to swap a KeyManager and TrustManager from a SSLContext, SSLSocketFactory and SSLServerSocketFactory while already using it within your client or server at runtime. This option will enable to refresh the identity and trust material of a server or client without the need of restarting your application or recreating it with SSLFactory. The identity and trust material may expire at some point in time and needs to be replaced to be still functional.
Restart of the application with a traditional setup is unavoidable and can result into a downtime for x amount of time. A restart is not needed when using the setup below.
```text
SSLFactory baseSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .withSwappableIdentityMaterial()
          .withSwappableTrustMaterial()
          .build();
          
HttpClient httpClient = HttpClient.newBuilder()
          .sslParameters(sslFactory.getSslParameters())
          .sslContext(sslFactory.getSslContext())
          .build()

// execute https request
HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());

SSLFactory updatedSslFactory = SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
          
// swap identity and trust materials and reuse existing http client
KeyManagerUtils.swapKeyManager(baseSslFactory.getKeyManager().get(), updatedSslFactory.getKeyManager().get());
TrustManagerUtils.swapTrustManager(baseSslFactory.getTrustManager().get(), updatedSslFactory.getTrustManager().get());

// Cleanup old ssl sessions by invalidating them all. Forces to use new ssl sessions which will be created by the swapped KeyManager/TrustManager
SSLSessionUtils.invalidateCaches(baseSslFactory.getSslContext());

HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());
```

See here for a basic reference implementation for a
server: [GitHub - Instant SSL Reloading](https://github.com/Hakky54/java-tutorials/tree/main/instant-server-ssl-reloading)

##### Trust additional new certificates at runtime

Although it is possible to reload the complete trust material as shown before
in [Reloading SSL at runtime](#support-for-reloading-ssl-at-runtime)
and [Hot swap KeyManager and TrustManager at runtime](#support-for-swapping-keymanager-and-trustmanager-at-runtime), in
some occasions you might want the trust additional new certificates without reloading all the trust material as it
might be redundant. Especially if you want to keep other trust material intact which is already loaded to your
SSLFactory and you don't want it to be reloaded. An example use case would be using the JDK and OS trusted Certificates
Authorities
and your custom truststore which can grow over time. See below for two examples:

##### Option 1

```text
SSLFactory sslFactory = SSLFactory.builder()
        .withDefaultTrustMaterial()
        .withSystemTrustMaterial()
        .withInflatableTrustMaterial()
        .build();

List<X509Certificate> certificates = ... ; // after some point in time you have a couple of new CA which you want to trust

TrustManagerUtils.addCertificate(sslFactory.getTrustManager().get(), certificates);
```

With the option below your newly trusted certificates will be also stored on the file-system.
If the file exists then it will first read and append to it. The predicate is thread-safe and can be used for example
prompting the user to trust the certificate if integrated in a GUI.

##### Option 2

```text
SSLFactory sslFactory = SSLFactory.builder()
        .withDefaultTrustMaterial()
        .withSystemTrustMaterial()
        .withInflatableTrustMaterial(Paths.get("/path/to/truststore.p12"), "password".toCharArray(), "PKCS12", trustManagerParameters -> {
            // do some validation to decide whether to trust this certificate
            return true;
        })
        .build();
```

A proof-of-concept is available here: [GitHub - Trust Me](https://github.com/Hakky54/trust-me) which demonstrates how it can be integrated in a GUI and prompting the end-user to either trust or reject the server certificate. It will be applied instantly and the ssl configuration will be reloaded.

##### Routing identity material to specific host

It may occur that the client is sending the wrong certificate to the server when using multiple identities. This will
happen when the client certificate has insufficient information for the underlying ssl engine (the KeyManager) and
therefore it cannot select the right certificate.
Recreating the certificates can resolve this issue. However, if that is not possible you can provide an option to the
engine to use a specific certificate for a given server. Below is an example setup for correctly routing the client
identity based on the alias which can be found within the KeyStore file.

```text
SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withTrustMaterial("truststore.jks", password)
          .withIdentityRoute("client-alias-one", "https://localhost:8443/", "https://localhost:8453/")
          .withIdentityRoute("client-alias-two", "https://localhost:8463/", "https://localhost:8473/")
          .build();
```
##### Updating identity routes at runtime
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withTrustMaterial("truststore.jks", password)
          .withIdentityRoute("client-alias-one", "https://localhost:8443/", "https://localhost:8453/")
          .withIdentityRoute("client-alias-two", "https://localhost:8463/", "https://localhost:8473/")
          .build();

X509ExtendedKeyManager keyManager = sslFactory.getKeyManager().get()

// Add additional routes next to the existing ones
KeyManagerUtils.addIdentityRoute(keyManager, "client-alias-one", "https://localhost:8463/", "https://localhost:8473/")

// Override existing routes
KeyManagerUtils.overrideIdentityRoute(keyManager, "client-alias-two", "https://localhost:9463/", "https://localhost:9473/")
```
##### Managing additional identities at runtime
Please beware when using multiple identities from a keystore. The alias name from the key entry within the keystore should be unique across all the identities.
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withInflatableIdentityMaterial()
          .withIdentityMaterial(Paths.get("/path/to/your/identity-1.jks"), "password".toCharArray())
          .withTrustMaterial("truststore.jks", password)
          .withIdentityRoute("client-alias-one", "https://localhost:8443/", "https://localhost:8453/")
          .build();
          
X509ExtendedKeyManager keyManager = sslFactory.getKeyManager().get();

// Adding identity and an additional route
KeyStore identityTwo = KeyStoreUtils.loadKeyStore(Paths.get("/path/to/your/identity-2.jks"), "password".toCharArray());
KeyManagerUtils.addIdentityMaterial(keyManager, "client-alias-two", identityTwo, "password".toCharArray());
KeyManagerUtils.addIdentityRoute(keyManager, "client-alias-two", "https://localhost:8463/", "https://localhost:8473/");

// Getting existing list of aliases from the inflatable key manager
List<String> aliases = KeyManagerUtils.getAliases(keyManager);

// Removing identity
KeyManagerUtils.removeIdentityMaterial(keyManager, "client-alias-two");
KeyManagerUtils.removeIdentityRoute(keyManager, "client-alias-two");
```
##### Managing ssl session
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withIdentityMaterial("identity.jks", "password".toCharArray())
          .withTrustMaterial("truststore.jks", "password".toCharArray())
          .withSessionTimeout(3600) // Amount of seconds until it will be invalidated
          .withSessionCacheSize(1024) // Amount of bytes until it will be invalidated
          .build();
          
SSLContext sslContext = sslFactory.getSslContext();
          
// Caches can be invalidated with the snippet below
SSLSessionUtils.invalidateCaches(sslContext);

// or any other option:
SSLSessionUtils.invalidateCachesBefore(
        sslContext,
        ZonedDateTime.of(LocalDateTime.of(2021, JANUARY, 1, 15, 55), ZoneOffset.UTC)
);

SSLSessionUtils.invalidateCachesAfter(
        sslContext,
        ZonedDateTime.of(LocalDateTime.of(2021, FEBRUARY, 10, 8, 14), ZoneOffset.UTC)
);

SSLSessionUtils.invalidateCachesBetween(
        sslContext,
        ZonedDateTime.now().minusHours(2),    // from
        ZonedDateTime.now()                   // up till
);
```
##### Extracting server certificates
###### Single server
```text
List<X509Certificate> certificates = CertificateUtils.getCertificatesFromExternalSource("https://github.com/");
```

###### Bulk extraction from multiple servers
```text
Map<String, List<X509Certificate>> certificates = CertificateUtils.getCertificatesFromExternalSources(
            "https://github.com/", 
            "https://stackoverflow.com/", 
            "https://www.reddit.com/",
            "https://www.youtube.com/");
```

###### Extracting certificates behind proxy
```text
Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("my-custom-host", 1234));
List<X509Certificate> certificates = CertificateUtils.getCertificatesFromExternalSource(proxy, "https://github.com/");
```

###### Extracting certificates behind proxy with authentication
```text
Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("my-custom-host", 1234));
PasswordAuthentication passwordAuthentication = new PasswordAuthentication("foo", "bar".toCharArray());
List<X509Certificate> certificates = CertificateUtils.getCertificatesFromExternalSource(proxy, passwordAuthentication, "https://github.com/");
```

###### Extracting certificates as pem
All previous examples are also available for extracting the server certificates as pem. The method has an additional `asPem` suffix. See below for all of the examples:
```text
// single
List<String> certificates = CertificateUtils.getCertificatesFromExternalSourceAsPem("https://github.com/");

// bulk
Map<String, List<X509Certificate>> urlsToCertificates = CertificateUtils.getCertificatesFromExternalSourcesAsPem(
            "https://github.com/", 
            "https://stackoverflow.com/", 
            "https://www.reddit.com/",
            "https://www.youtube.com/");
    
// proxy        
Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("my-custom-host", 1234));
certificates = CertificateUtils.getCertificatesFromExternalSource(proxy, "https://github.com/");

// proxy + authentication
PasswordAuthentication passwordAuthentication = new PasswordAuthentication("foo", "bar".toCharArray());
certificates = CertificateUtils.getCertificatesFromExternalSource(proxy, passwordAuthentication, "https://github.com/");
```

See here also for a demo application for the CLI: [GitHub - Certificate Ripper](https://github.com/Hakky54/certificate-ripper)

#### Using P7B or PKCS#7 Files
Support for using p7b formatted certificates and certificate-chain from classpath, any directory or as an InputStream. 
P7b file is a text file containing a `-----BEGIN PKCS7-----` as header, `-----END PKCS7-----` as footer and has a Base64 encoded data between it.
```
List<Certificate> certificates = CertificateUtils.loadCertificate("certificate.p7b");

SSLFactory.builder()
          .withTrustMaterial(certificates)
          .build();
```

#### Using DER Files
Support for using der formatted certificates and certificate-chain from classpath, any directory or as an InputStream.
Der file is a binary form of a certificate. Commonly used extensions are `.cer` and `crt`.
```
List<Certificate> certificates = CertificateUtils.loadCertificate("certificate.cer");

SSLFactory.builder()
          .withTrustMaterial(certificates)
          .build();
```

#### Using PFX, P12 or PKCS#12 Files
PFX and p12 are both PKCS#12 type keystores which are supported.

```text
SSLFactory.builder()
          .withIdentityMaterial("identity.p12", "password".toCharArray())
          .withTrustMaterial("truststore.p12", "password".toCharArray())
          .build();
```

#### Using PEM Files

Support for using pem formatted private key and certificates from classpath, any directory or as an InputStream.
See [PemUtilsShould](ayza-for-pem/src/test/java/nl/altindag/ssl/pem/util/PemUtilsShould.java) for
detailed usages.
Add the dependency below to use this feature, it also includes the core features from the library such as SSLFactory.
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
  <artifactId>ayza-for-pem</artifactId>
  <version>10.0.2</version>
</dependency>
```
##### Loading pem files from the classpath
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("certificate.pem", "private-key.pem");
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial("some-trusted-certificate.pem");

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustMaterial(trustManager)
          .build();
```
##### Loading pem files from anywhere on the filesystem
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(Paths.get("/path/to/your/certificate.pem"), Paths.get("/path/to/your/private-key.pem"));
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(Paths.get("/path/to/your/some-trusted-certificate.pem"));
```
##### Loading pem files from InputStream
```
InputStream privateKey = ...
InputStream certificate = ...
InputStream trustedCertificates = ...

X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificate, privateKey);
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(trustedCertificates);
```
##### Loading pem files from string content
```
String privateKey =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
        "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIy3Fposf+2ccCAggA\n" +
        "-----END ENCRYPTED PRIVATE KEY-----\n";

String certificate =
        "-----BEGIN CERTIFICATE-----\n" +
        "g0Y2YBH5v0xmi8sYU7weOcwynkjZARpUltBUQ0pWCF5uJsEB8uE8PPDD3c4=\n" +
        "-----END CERTIFICATE-----\n";

String trustedCertificates =
        "-----BEGIN CERTIFICATE-----\n" +
        "CC01zojqS10nGowxzOiqyB4m6wytmzf0QwjpMw==\n" +
        "-----END CERTIFICATE-----\n";

X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(certificate, privateKey, "secret".toCharArray());
X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(trustedCertificates);
```
##### Loading encrypted pem files
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("certificate.pem", "private-key.pem", "secret".toCharArray());
```
##### Migrating from classic configuration
Below is an example of the classic configuration for enabling ssl for your application.
```
-Djavax.net.ssl.trustStore=/path/to/truststore.jks
-Djavax.net.ssl.trustStoreType=jks
-Djavax.net.ssl.trustStorePassword=changeit
-Djavax.net.ssl.trustStoreProvider=SunJSSE

-Djavax.net.ssl.keyStore=/path/to/keystore.jks
-Djavax.net.ssl.keyStoreType=jks
-Djavax.net.ssl.keyStorePassword=changeit
-Djavax.net.ssl.keyStoreProvider=SunJSSE

-Dhttps.protocols=TLSv1.3
-Dhttps.cipherSuites=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
```

SSLFactory can be used with these properties together with the existing properties with the following snippet:
```
SSLFactory sslFactory = SSLFactory.builder()
        .withSystemPropertyDerivedIdentityMaterial()
        .withSystemPropertyDerivedTrustMaterial()
        .withSystemPropertyDerivedProtocols()
        .withSystemPropertyDerivedCiphers()
        .build();

SSLContext.setDefault(sslFactory.getSslContext());
```

The SSLFactory returnable values can be supplied to the http client as shown [here](#tested-http-clients)

##### Global SSL configuration
If it is not possible to adjust the ssl configuration of a server or client because it is using the default ssl configuration or using a pre-configured, then you can give the snippet below a try.
The snippet below will ensure the default SSLContext will be the one which is constructed by SSLFactory and the Security utility of Java will also use the SSLContext of SSLFactory if it is initialized with `SSLContext.getInstance("TLS")` or any of the following protocols: SSL, SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3
See also a working demo here: [Bypassing and overruling SSL configuration of libraries](https://github.com/Hakky54/java-tutorials/tree/main/bypassing-overruling-ssl-configuration)
```
// The SSLFactory below is just an example, use your own custom initialized one here
SSLFactory sslFactory = SSLFactory.builder()
        .withDefaultTrustMaterial()
        .withSystemTrustMaterial()
        .build();

Provider provider = ProviderUtils.create(sslFactory);
Security.insertProviderAt(provider, 1);
SSLContext.setDefault(sslFactory.getSslContext());
```

##### Logging detailed certificate validation
```text
SSLFactory sslFactory = SSLFactory.builder()
        .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
        .withLoggingTrustMaterial()
        .build();
        
// run your server or client and analyse the logs
```

You will get a log message which is similar to the following one:
```text
Validating the certificate chain of the server[google.com:443] with authentication type RSA, while also using the SSLEngine. See below for the full chain of the server:
[[
[
  Version: V3
  Subject: CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US
  Signature Algorithm: SHA256withRSA, OID = 1.2.840.113549.1.1.11

  Key:  Sun EC public key, 256 bits
  public x coord: 54347275970077566368513898626765286548687250565786921039060191273785455056345
  public y coord: 88043846562958291988419087726639688241289668084120802006631053348150453315748
  parameters: secp256r1 [NIST P-256, X9.62 prime256v1] (1.2.840.10045.3.1.7)
  Validity: [From: Wed Oct 16 14:36:57 CEST 2019,
               To: Wed Jan 08 13:36:57 CET 2020]
  Issuer: CN=GTS CA 1O1, O=Google Trust Services, C=US
  SerialNumber: [    a2b1428b 94a636b2 08000000 0019fa68]

Certificate Extensions: 10
[1]: ObjectId: 1.3.6.1.4.1.11129.2.4.2 Criticality=false
Extension unknown: DER encoded OCTET string =
0000: 04 81 F5 04 81 F2 00 F0   00 76 00 B2 1E 05 CC 8B  .........v......
0010: A2 CD 8A 20 4E 87 66 F9   2B B9 8A 25 20 67 6B DA  ... N.f.+..% gk.
0020: FA 70 E7 B2 49 53 2D EF   8B 90 5E 00 00 01 6D D4  .p..IS-...^...m.
0030: C9 39 F6 00 00 04 03 00   47 30 45 02 20 3B E9 89  .9......G0E. ;..
0040: 83 7B 8C F6 11 AC C5 2C   2E 8C 21 E9 DE 24 3F E2  .......,..!..$?.
0050: 3B 46 6C 20 86 36 38 A3   E2 39 89 80 13 02 21 00  ;Fl .68..9....!.
0060: C0 B8 0E AC C3 71 A9 66   B3 49 AE 46 2F FF CE 35  .....q.f.I.F/..5
0070: CE C0 CD 5B 3E AA 3B 33   1B CC A4 7E E2 62 98 78  ...[>.;3.....b.x
0080: 00 76 00 5E A7 73 F9 DF   56 C0 E7 B5 36 48 7D D0  .v.^.s..V...6H..
0090: 49 E0 32 7A 91 9A 0C 84   A1 12 12 84 18 75 96 81  I.2z.........u..
00A0: 71 45 58 00 00 01 6D D4   C9 39 99 00 00 04 03 00  qEX...m..9......
00B0: 47 30 45 02 20 1B 76 BF   FD 79 76 D9 A0 A1 6D F7  G0E. .v..yv...m.
00C0: F2 33 67 55 DD 38 7A F5   98 E0 28 05 25 DD 3D 8B  .3gU.8z...(.%.=.
00D0: A5 91 BC DF 2E 02 21 00   87 81 AD 92 A6 1D 6B A0  ......!.......k.
00E0: 32 75 B8 68 FF 5C D2 F6   FA 11 0E FF 44 2D 7D DB  2u.h.\......D-..
00F0: 9C 1A 27 3A D3 32 CB B7                            ..':.2..


[2]: ObjectId: 1.3.6.1.5.5.7.1.1 Criticality=false
AuthorityInfoAccess [
  [
   accessMethod: ocsp
   accessLocation: URIName: http://ocsp.pki.goog/gts1o1
, 
   accessMethod: caIssuers
   accessLocation: URIName: http://pki.goog/gsr2/GTS1O1.crt
]
]

[3]: ObjectId: 2.5.29.35 Criticality=false
AuthorityKeyIdentifier [
KeyIdentifier [
0000: 98 D1 F8 6E 10 EB CF 9B   EC 60 9F 18 90 1B A0 EB  ...n.....`......
0010: 7D 09 FD 2B                                        ...+
]
]

[4]: ObjectId: 2.5.29.19 Criticality=true
BasicConstraints:[
  CA:false
  PathLen: undefined
]

[5]: ObjectId: 2.5.29.31 Criticality=false
CRLDistributionPoints [
  [DistributionPoint:
     [URIName: http://crl.pki.goog/GTS1O1.crl]
]]

[6]: ObjectId: 2.5.29.32 Criticality=false
CertificatePolicies [
  [CertificatePolicyId: [2.23.140.1.2.2]
[]  ]
  [CertificatePolicyId: [1.3.6.1.4.1.11129.2.5.3]
[]  ]
]

[7]: ObjectId: 2.5.29.37 Criticality=false
ExtendedKeyUsages [
  serverAuth
]

[8]: ObjectId: 2.5.29.15 Criticality=true
KeyUsage [
  DigitalSignature
]

[9]: ObjectId: 2.5.29.17 Criticality=false
SubjectAlternativeName [
  DNSName: *.google.com
]

[10]: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: BA 16 19 65 61 DB B1 32   D3 8E E7 C6 A6 A5 CC A4  ...ea..2........
0010: 3F 19 20 73                                        ?. s
]
]

]
  Algorithm: [SHA256withRSA]
  Signature:
0000: 52 3B 09 75 6D 73 2C 57   CE F5 6B F3 1F A8 5C FD  R;.ums,W..k...\.
0010: 0F F7 78 6D 02 9F DB 19   99 B1 9B A2 A5 42 7A 3B  ..xm.........Bz;
0020: 0C 92 2C 65 F6 36 B8 15   28 5B 63 D2 7A 9D 34 94  ..,e.6..([c.z.4.
0030: 6E 2E 40 82 E0 90 95 BE   B7 27 85 01 8F D7 25 6A  n.@......'....%j
0040: 74 11 06 92 2C 6B 2F E7   D7 D3 AD BD 89 B3 C5 1F  t...,k/.........
0050: 57 9B BB C6 43 79 8B 34   42 41 1C 80 A8 01 77 03  W...Cy.4BA....w.
0060: 10 34 95 C4 B2 67 31 9D   2B 3B 5A 77 9D 96 7C 14  .4...g1.+;Zw....
0070: F4 9A F3 E3 1C 18 08 60   CB 63 E1 17 EB 5C C2 B9  .......`.c...\..
0080: 21 4D 22 05 D7 63 E1 5B   D7 DD A6 E1 46 48 17 7D  !M"..c.[....FH..
0090: 10 54 FA 08 E3 43 DD F2   C7 41 A1 42 F7 EC D2 70  .T...C...A.B...p
00A0: 5E 4A FB 8B 85 2E F4 A1   D1 3E AD 4E 39 72 21 AF  ^J.......>.N9r!.
00B0: B7 5B 9E 7D EB C0 29 91   7C 75 9F F7 7A 94 8C 46  .[....)..u..z..F
00C0: FA 0B F7 A3 E9 49 6D B7   5D FE 68 49 E1 9F 18 B2  .....Im.].hI....
00D0: A0 50 EB 93 8D 71 53 84   A2 34 C4 F8 C9 08 9D 5F  .P...qS..4....._
00E0: 9B 2A 37 5E E0 F8 5D F5   7A 7D BC EB 3D 78 5C 23  .*7^..].z...=x\#
00F0: 84 DD CC 32 97 6C 77 92   7C 06 E4 5D 52 A0 5A 39  ...2.lw....]R.Z9

]]
```

##### Logging detailed KeyManager flow, input and output
```text
SSLFactory sslFactory = SSLFactory.builder()
        .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
        .withLoggingIdentityMaterial()
        .withDefaultTrustMaterial()
        .build();
        
// run your server or client and analyse the logs
```

You will get a log message which is similar to the following one:
```text
Attempting to find a client alias for key types [EC], while also using the Socket. See below for list of the issuers:
[CN=some-cn, OU=java-business-unit, O=thunderberry, C=NL]
Attempting to find a client alias for key types [RSA], while also using the Socket. See below for list of the issuers:
[CN=some-cn, OU=java-business-unit, O=thunderberry, C=NL]
Found the following client aliases [my-client-alias] for key types [RSA], while also using the Socket. See below for list of the issuers:
[CN=some-cn, OU=java-business-unit, O=thunderberry, C=NL]
Attempting to get the private key for the alias: my-client-alias
Found a private key for the alias: my-client-alias
Attempting to get the certificate chain for the alias: my-client-alias
Found the certificate chain with a size of 1 for the alias: my-client-alias. See below for the full chain:
[[
[
  Version: V3
  Subject: CN=some-cn, OU=java-business-unit, O=thunderberry, C=NL
  Signature Algorithm: SHA256withRSA, OID = 1.2.840.113549.1.1.11

  Key:  Sun RSA public key, 2048 bits
  params: null
  modulus: 24358361148173123789972454702359337497482540111137434929916055417657354571697209833398713022918665517266658129513432713825681637659966415899913132315999013865220594646161546243646863695313013179456071195691453898185614193141245291456731398570603932104743113343898797041713131938343069988939700047591424592896073860712253945927117061051481828014230668012078029149888844657841672769678941972627103264098329661131121121108364416406527046714029325801099459715576059589001573317998720822010338410175438085716969314224320362271384261147189938038370804394737540861857893390249061609350687279289599644929221019981684263046077
  public exponent: 65537
  Validity: [From: Mon Feb 08 18:14:16 CET 2021,
               To: Thu Feb 06 18:14:16 CET 2031]
  Issuer: CN=some-cn, OU=java-business-unit, O=thunderberry, C=NL
  SerialNumber: [    3a03c719]

Certificate Extensions: 3
[1]: ObjectId: 2.5.29.37 Criticality=false
ExtendedKeyUsages [
  serverAuth
  clientAuth
]

[2]: ObjectId: 2.5.29.15 Criticality=false
KeyUsage [
  DigitalSignature
  Key_Encipherment
  Data_Encipherment
  Key_Agreement
]

[3]: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 6C D2 C6 3D 90 94 1F C9   43 9A A8 A3 41 3E BC 93  l..=....C...A>..
0010: FF E9 00 9E                                        ....
]
]

]
  Algorithm: [SHA256withRSA]
  Signature:
0000: 5F CD B8 0D 27 23 46 81   80 96 A0 E3 4D 79 82 F3  _...'#F.....My..
0010: AC E4 FC 53 B6 8B 17 FD   88 E7 03 DF B5 A6 DC 78  ...S...........x
0020: 75 D7 57 BE 14 C6 12 44   A3 25 E2 9B 2B E1 F1 FA  u.W....D.%..+...
0030: 68 19 19 F3 1B E7 67 17   8F 12 F6 C7 82 CA B7 E2  h.....g.........
0040: F9 66 44 09 3C D7 0F E1   0B FB CF 4B 58 37 79 32  .fD.<......KX7y2
0050: DC E1 E1 CD 97 9B 99 C8   95 DA F3 0E 74 0D 36 7E  ............t.6.
0060: A4 E0 DA BC 66 A0 CD AD   0C BE 6D C5 12 7E F2 6E  ....f.....m....n
0070: AC 89 00 55 1B 1A 23 CA   26 0D B3 B8 E5 52 8C F6  ...U..#.&....R..
0080: 20 D3 ED A3 D7 CD 55 2F   2D EB 07 12 1E 70 C6 0E   .....U/-....p..
0090: 1F 3C AB 8C 23 2F 15 19   A4 F6 4E B0 0E F5 2A D9  .<..#/....N...*.
00A0: E1 F2 50 A9 BC 6D 7A 24   CA CA 07 69 61 0E 55 C5  ..P..mz$...ia.U.
00B0: C3 36 72 2D B8 4A 93 2E   19 45 F9 49 C1 C8 14 15  .6r-.J...E.I....
00C0: 99 C7 06 8D 2A 93 08 87   0B 89 BE 3D 72 01 A5 E7  ....*......=r...
00D0: 97 2A B3 EA 63 92 45 32   D3 58 55 BE BB 69 B8 21  .*..c.E2.XU..i.!
00E0: 5A 98 D2 7D 0B 8D BD 23   A2 3B C3 53 94 5A 54 BA  Z......#.;.S.ZT.
00F0: F2 FD 48 AD 59 F6 E1 CB   86 BF EF 12 0E BD 69 1E  ..H.Y.........i.

]]
```

### Fluently mapping SSLFactory
The SSLFactory can be mapped easily if it needs additional intermediate steps before it can be used fully used, such as using it with a Netty or Apache client. Below is an example for Netty with Spring WebClient.

```java
import io.netty.handler.ssl.SslContext;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.netty.util.NettySslUtils;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

public class App {
    
    public static void main(String[] args) throws SSLException {
      WebClient webClient = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build()
                .map(NettySslUtils::forClient)
                .map(SslContextBuilder::build)
                .map(sslContext -> HttpClient.create().secure(sslSpec -> sslSpec.sslContext(sslContext)))
                .map(ReactorClientHttpConnector::new)
                .map(httpConnector -> WebClient.builder().clientConnector(httpConnector).build()) 
                .get();
    }

}
```


### Returnable values from the SSLFactory
The SSLFactory provides different kinds of returnable values, see below for all the options:

```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.model.KeyStoreHolder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystore.p12", "secret".toCharArray(), "PKCS12")
                .withTrustMaterial("truststore.p12", "secret".toCharArray(), "PKCS12")
                .build();

        SSLContext sslContext = sslFactory.getSslContext();
        HostnameVerifier hostnameVerifier = sslFactory.getHostnameVerifier();
        Optional<X509ExtendedKeyManager> keyManager = sslFactory.getKeyManager();
        Optional<X509ExtendedTrustManager> trustManager = sslFactory.getTrustManager();
        Optional<KeyManagerFactory> keyManagerFactory = sslFactory.getKeyManagerFactory();
        Optional<TrustManagerFactory> trustManagerFactory = sslFactory.getTrustManagerFactory();
        List<X509Certificate> trustedCertificates = sslFactory.getTrustedCertificates();
        SSLSocketFactory sslSocketFactory = sslFactory.getSslSocketFactory();
        SSLServerSocketFactory sslServerSocketFactory = sslFactory.getSslServerSocketFactory();
        SSLEngine sslEngine = sslFactory.getSslEngine(host, port);
        SSLParameters sslParameters = sslFactory.getSslParameters();
        List<String> ciphers = sslFactory.getCiphers();
        List<String> protocols = sslFactory.getProtocols();
    }

}
```

### Additional mappers for specific libraries
Some http clients relay on different ssl classes from third parties and require mapping from SSLFactory to those libraries.
Below you will find the maven dependency which will provide the mapping and also the SSLFactory library.
#### Netty
Some know http clients which relay on netty libraries are: [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html), [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) and [Dispatch Reboot Http Client](https://github.com/dispatch/reboot).
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
  <artifactId>ayza-for-netty</artifactId>
  <version>10.0.2</version>
</dependency>
```
Example setup for Spring WebClient with Netty:
```java
import io.netty.handler.ssl.SslContext;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.netty.util.NettySslUtils;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

public class App {
    
    public static void main(String[] args) throws SSLException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        SslContext sslContext = NettySslUtils.forClient(sslFactory).build();
        HttpClient httpClient = HttpClient.create()
                .secure(sslSpec -> sslSpec.sslContext(sslContext));

        WebClient webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

}
```

#### Jetty
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
  <artifactId>ayza-for-jetty</artifactId>
  <version>10.0.2</version>
</dependency>
```
Example setup for [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html):
```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.jetty.util.JettySslUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.http.client.reactive.JettyClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();
        
        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);
        HttpClient httpClient = new HttpClient(sslContextFactory);

        WebClient webClient = WebClient.builder()
                .clientConnector(new JettyClientHttpConnector(httpClient))
                .build();
    }

}
```

#### Apache
##### Apache 4
Apache Http Client works with javax.net.ssl.SSLContext, so an additional mapping to their library is not required.
However, it is still possible to configure the http client with their custom configuration class. you can find below an example configuration for that use case:
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
  <artifactId>ayza-for-apache4</artifactId>
  <version>10.0.2</version>
</dependency>
```
```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.apache4.util.Apache4SslUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        LayeredConnectionSocketFactory socketFactory = Apache4SslUtils.toSocketFactory(sslFactory);

        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();
    }

}
```
##### Apache 5
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
  <artifactId>ayza-for-apache5</artifactId>
  <version>10.0.2</version>
</dependency>
```
```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.apache5.util.Apache5SslUtils;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        PoolingAsyncClientConnectionManager connectionManager = PoolingAsyncClientConnectionManagerBuilder.create()
                .setTlsStrategy(Apache5SslUtils.toTlsStrategy(sslFactory))
                .build();
        
        CloseableHttpAsyncClient httpAsyncClient = HttpAsyncClients.custom()
                .setConnectionManager(connectionManager)
                .build();
        
        httpAsyncClient.start();
    }

}
```

## Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) and the [service directory](https://github.com/Hakky54/mutual-tls-ssl/tree/master/client/src/main/java/nl/altindag/client/service) for detailed configuration

**Java**
* [Apache HttpClient](https://hc.apache.org/httpcomponents-client-4.5.x/index.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L68) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheHttpClientService.java)
* [Apache HttpAsyncClient](https://hc.apache.org/httpcomponents-asyncclient-4.1.x/index.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L76) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheHttpAsyncClientService.java)
* [Apache 5 HttpClient](https://hc.apache.org/httpcomponents-client-5.0.x/examples.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L86) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Apache5HttpClientService.java)
* [Apache 5 HttpAsyncClient](https://hc.apache.org/httpcomponents-client-5.0.x/examples-async.html) -> [Client configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L97) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Apache5HttpAsyncClientService.java)
* [JDK HttpClient](https://openjdk.java.net/groups/net/httpclient/intro.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L111) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JdkHttpClientService.java)
* [Old JDK HttpClient](https://docs.oracle.com/javase/tutorial/networking/urls/readingWriting.html) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJdkHttpClientService.java)
* [Netty Reactor](https://github.com/reactor/reactor-netty) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L134) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ReactorNettyService.java)
* [Jetty Reactive HttpClient](https://github.com/jetty-project/jetty-reactive-httpclient) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L142) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JettyReactiveHttpClientService.java)
* [Spring RestTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/client/RestTemplate.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L119) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringRestTemplateService.java)
* [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L148) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L155) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SpringWebClientService.java)
* [OkHttp](https://github.com/square/okhttp) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L125) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OkHttpClientService.java)
* [Jersey Client](https://eclipse-ee4j.github.io/jersey/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L162) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/JerseyClientService.java)
* Old Jersey Client -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L170) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/OldJerseyClientService.java)
* [Apache CXF JAX-RS](https://cxf.apache.org/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L182) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheCXFJaxRsClientService.java)
* [Apache CXF using ConduitConfigurer](https://cxf.apache.org/) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L191) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ApacheCXFWebClientService.java)
* [Google HttpClient](https://github.com/googleapis/google-http-java-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L206) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/GoogleHttpClientService.java)
* [Unirest](https://github.com/Kong/unirest-java) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L214) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/UnirestService.java)
* [Retrofit](https://github.com/square/retrofit) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L224) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/RetrofitService.java)
* [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L262) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AsyncHttpClientService.java)
* [Feign](https://github.com/OpenFeign/feign) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L272) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FeignService.java)
* [Methanol](https://github.com/mizosoft/methanol) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L308) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/MethanolService.java)
* [Vertx Webclient](https://github.com/vert-x3/vertx-web) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L316) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/VertxWebClientService.java)
* [gRPC](https://grpc.io/) -> [Client/Server Configuration & Example request](https://github.com/Hakky54/java-tutorials)
* [ElasticSearch](https://www.elastic.co/) -> [RestHighLevelClient Configuration & example request](https://github.com/Hakky54/java-tutorials/blob/main/elasticsearch-with-ssl/src/main/java/nl/altindag/ssl/es/App.java)
* [Jetty WebSocket](https://www.eclipse.org/jetty/) -> [Client configuration & example request](https://github.com/Hakky54/java-tutorials/blob/2bf5d975347d500bb9d0aa3b32cbf33b345425ee/websocket-client-with-ssl/src/main/java/nl/altindag/ssl/ws/App.java#L14)

**Kotlin**
* [Fuel](https://github.com/kittinunf/fuel) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FuelService.kt)
* [Http4k with Apache 4](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache4HttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with Async Apache 4](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache4AsyncHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kAsyncClientService.kt)
* [Http4k with Apache 5](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache5HttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with Async Apache 5](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kApache5AsyncHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kAsyncClientService.kt)
* [Http4k with Java Net](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kJavaHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with Jetty](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kJettyHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Http4k with OkHttp](https://github.com/http4k/http4k) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kOkHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4kClientService.kt)
* [Kohttp](https://github.com/rybalkinsd/kohttp) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KohttpService.kt)
* [Ktor with Android engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorAndroidHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with Apache engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorApacheHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with CIO (Coroutine-based I/O) engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorCIOHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with Java engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorJavaHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)
* [Ktor with Okhttp engine](https://github.com/ktorio/ktor) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorOkHttpClientService.kt) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/KtorHttpClientService.kt)

**Scala**
* [Twitter Finagle](https://github.com/twitter/finagle) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L233) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/FinagleHttpClientService.java)
* [Twitter Finagle Featherbed](https://github.com/finagle/featherbed) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/d78e4e81b8b775d3ff09c11b0a7c1532a741199e/client/src/main/java/nl/altindag/client/service/FeatherbedRequestService.scala#L19)
* [Akka Http Client](https://github.com/akka/akka-http) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/35cba2f3a2dcd73b01fa323b99eec7777f7429bb/client/src/main/java/nl/altindag/client/ClientConfig.java#L253) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/AkkaHttpClientService.java)
* [Dispatch Reboot](https://github.com/dispatch/reboot) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/DispatchRebootService.scala)
* [ScalaJ / Simplified Http Client](https://github.com/scalaj/scalaj-http) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/ScalaJHttpClientService.scala)
* [Sttp](https://github.com/softwaremill/sttp) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/SttpHttpClientService.scala)
* [Requests-Scala](https://github.com/lihaoyi/requests-scala) -> [Client Configuration & Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/RequestsScalaService.scala)
* [Http4s Blaze Client](https://github.com/http4s/http4s) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sBlazeClientService.scala) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sService.scala)
* [Http4s Java Net Client](https://github.com/http4s/http4s) -> [Client Configuration](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sJavaNetClientService.scala) | [Example request](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/service/Http4sService.scala)

There is a github project available named [Mutual-tls-ssl](https://github.com/Hakky54/mutual-tls-ssl) which provides a tutorial containing steps for setting up these four scenarios:
* No security
* One way authentication
* Two way authentication
* Two way authentication with trusting the Certificate Authority

It will also explain how to create KeyStores, Certificates, Certificate Signing Requests and how to implement it.

## Contributing

There are plenty of ways to contribute to this project:

* Give it a star
* Make a donation through [GitHub](https://github.com/sponsors/Hakky54) or [open collective](https://opencollective.com/hakky54)
* Join the [Gitter room](https://gitter.im/hakky54/ayza) and leave a feedback or help with answering users questions
* Submit a PR

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/MrR0807"><img src="https://avatars.githubusercontent.com/u/24605837?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Laurynas</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3AMrR0807" title="Code">💻</a> <a href="#maintenance-MrR0807" title="Maintenance">🚧</a></td>
    <td align="center"><a href="https://github.com/charphi"><img src="https://avatars.githubusercontent.com/u/8778378?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Philippe Charles</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Acharphi" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="http://tadhgpearson.wordpress.com"><img src="https://avatars.githubusercontent.com/u/1496586?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Tadhg Pearson</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Atadhgpearson" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/winster"><img src="https://avatars.githubusercontent.com/u/2383613?v=4?s=100" width="100px;" alt=""/><br /><sub><b>winster</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Awinster" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/lalloni"><img src="https://avatars.githubusercontent.com/u/84328?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Pablo Lalloni</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Alalloni" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/luismospinam"><img src="https://avatars.githubusercontent.com/u/25059970?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Luis Miguel Ospina</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Aluismospinam" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/Athou"><img src="https://avatars.githubusercontent.com/u/1256795?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Jérémie Panzer</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3AAthou" title="Ideas, Planning, & Feedback">🤔</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/patpatpat123"><img src="https://avatars.githubusercontent.com/u/43899031?v=4?s=100" width="100px;" alt=""/><br /><sub><b>patpatpat123</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Apatpatpat123" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/Hakky54/ayza/issues?q=author%3Apatpatpat123" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://codyaray.com"><img src="https://avatars.githubusercontent.com/u/44062?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Cody A. Ray</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/search?q=Cody%20Ray" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/chibenwa"><img src="https://avatars.githubusercontent.com/u/6928740?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Benoit Tellier</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Achibenwa" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/sal0max"><img src="https://avatars.githubusercontent.com/u/423373?v=4?s=100" width="100px;" alt=""/><br /><sub><b>sal0max</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Asal0max" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/lhstack"><img src="https://avatars.githubusercontent.com/u/42345796?v=4?s=100" width="100px;" alt=""/><br /><sub><b>lhstack</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Alhstack" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/dasteg"><img src="https://avatars.githubusercontent.com/u/3967403?v=4?s=100" width="100px;" alt=""/><br /><sub><b>dasteg</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Adasteg" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/rymsha"><img src="https://avatars.githubusercontent.com/u/2891483?v=4?s=100" width="100px;" alt=""/><br /><sub><b>rymsha</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Arymsha" title="Ideas, Planning, & Feedback">🤔</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/manbucy"><img src="https://avatars.githubusercontent.com/u/24501621?v=4?s=100" width="100px;" alt=""/><br /><sub><b>manbucy</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Amanbucy" title="Code and Bug reports">🐛 💻</a></td>
    <td align="center"><a href="https://github.com/swankjesse"><img src="https://avatars.githubusercontent.com/u/133019?v=4?s=100" width="100px;" alt=""/><br /><sub><b>swankjesse</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Aswankjesse" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/ivenhov"><img src="https://avatars.githubusercontent.com/u/778457?v=4?s=100" width="100px;" alt=""/><br /><sub><b>ivenhov</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Aivenhov" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/ecki"><img src="https://avatars.githubusercontent.com/u/361432?v=4?s=100" width="100px;" alt=""/><br /><sub><b>ecki</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Aecki" title="Code and Bug reports">🐛 💻</a></td>
    <td align="center"><a href="https://github.com/mbenson"><img src="https://avatars.githubusercontent.com/u/487462?v=4?s=100" width="100px;" alt=""/><br /><sub><b>mbenson</b></sub></a><br /> <a href="https://github.com/Hakky54/ayza/issues?q=author%3Ambenson" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/Hakky54/ayza/issues?q=author%3Ambenson" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/EugenMayer"><img src="https://avatars.githubusercontent.com/u/136934?v=4?s=100" width="100px;" alt=""/><br /><sub><b>EugenMayer</b></sub></a><br /> <a href="https://github.com/Hakky54/ayza/issues?q=author%3AEugenMayer" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/bjorndarri"><img src="https://avatars.githubusercontent.com/u/2327926?v=4?s=100" width="100px;" alt=""/><br /><sub><b>bjorndarri</b></sub></a><br /> <a href="https://github.com/Hakky54/ayza/issues?q=bjorndarri" title="Code and Ideas, Planning, & Feedback">🤔 💻</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/henryju"><img src="https://avatars.githubusercontent.com/u/281596?v=4?s=100" width="100px;" alt=""/><br /><sub><b>henryju</b></sub></a><br /> <a href="https://github.com/Hakky54/ayza/issues?q=author%3Ahenryju" title="Code and Ideas, Planning, & Feedback">🤔 💻</a></td>
    <td align="center"><a href="https://github.com/nquinquenel"><img src="https://avatars.githubusercontent.com/u/14952624?v=4?s=100" width="100px;" alt=""/><br /><sub><b>nquinquenel</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Anquinquenel" title="Code and Bug reports">🐛 💻</a></td>
    <td align="center"><a href="https://github.com/woj-tek"><img src="https://avatars.githubusercontent.com/u/724413?v=4?s=100" width="100px;" alt=""/><br /><sub><b>woj-tek</b></sub></a><br /><a title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/thahnen"><img src="https://avatars.githubusercontent.com/u/6588381?v=4?s=100" width="100px;" alt=""/><br /><sub><b>thahnen</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Athahnen" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/gerardnorton"><img src="https://avatars.githubusercontent.com/u/62466694?v=4?s=100" width="100px;" alt=""/><br /><sub><b>gerardnorton</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Agerardnorton" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/austinarbor"><img src="https://avatars.githubusercontent.com/u/11469880?v=4?s=100" width="100px;" alt=""/><br /><sub><b>austinarbor</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Aaustinarbor" title="Bug reports and Ideas, Planning, & Feedback">🐛 🤔</a></td>
    <td align="center"><a href="https://github.com/ssmoss"><img src="https://avatars.githubusercontent.com/u/8904909?v=4?s=100" width="100px;" alt=""/><br /><sub><b>ssmoss</b></sub></a><br /><a href="https://github.com/Hakky54/ayza/issues?q=author%3Assmoss" title="Ideas, Planning, & Feedback">🤔</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/maxxedev"><img src="https://avatars.githubusercontent.com/u/5051664?v=4?s=100" width="100px;" alt=""/><br /><sub><b>maxxedev</b></sub></a><br /> <a href="https://github.com/Hakky54/ayza/issues?q=author%3Amaxxedev" title="Ideas, Planning, & Feedback">🤔</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FHakky54%2Fayza.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FHakky54%2Fayza?ref=badge_large)