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

import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;

import java.security.KeyStore;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author Hakan Altindag
 */
enum OperatingSystem {

    MAC(MacCertificateUtils.getInstance()),
    LINUX(LinuxCertificateUtils.getInstance()),
    ANDROID(AndroidCertificateUtils.getInstance()),
    WINDOWS(WindowsCertificateUtils.getInstance()),
    UNKNOWN(null);

    private static final Logger LOGGER = LoggerFactory.getLogger(OperatingSystem.class);

    private final OSCertificateUtils osCertificateUtils;

    OperatingSystem(OSCertificateUtils osCertificateUtils) {
        this.osCertificateUtils = osCertificateUtils;
    }

    static String getResolvedOsName() {
        return System.getProperty("os.name").toLowerCase();
    }

    static OperatingSystem get() {
        String operatingSystem = getResolvedOsName();
        if (operatingSystem.contains("windows")) {
            return WINDOWS;
        }

        if (operatingSystem.contains("mac")) {
            return MAC;
        }

        if (operatingSystem.contains("linux")) {
            String javaVendor = System.getProperty("java.vendor", "").toLowerCase();
            String javaVmVendor = System.getProperty("java.vm.vendor", "").toLowerCase();
            String javaRuntimeName = System.getProperty("java.runtime.name", "").toLowerCase();

            if (javaVendor.equals("the android project")
                    || javaVmVendor.equals("the android project")
                    || javaRuntimeName.equals("android runtime")) {

                return ANDROID;
            } else {
                return LINUX;
            }
        }

        return UNKNOWN;
    }

    List<KeyStore> getTrustStores() {
        return getOsCertificateUtils()
                .map(OSCertificateUtils::getTrustStores)
                .orElseGet(() -> {
                    String resolvedOsName = getResolvedOsName();
                    LOGGER.warn(String.format("No system KeyStores available for [%s]", resolvedOsName));
                    return Collections.emptyList();
                });
    }

    Optional<OSCertificateUtils> getOsCertificateUtils() {
        return Optional.ofNullable(osCertificateUtils);
    }

}
