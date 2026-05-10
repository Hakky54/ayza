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

import nl.altindag.ssl.SSLFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.LongFunction;
import java.util.function.Predicate;

import static nl.altindag.laleler.CollectorsUtils.toUnmodifiableList;

/**
 * @author Hakan Altindag
 */
public final class SSLSessionUtils {

    private static final LongFunction<ZonedDateTime> EPOCH_TIME_MAPPER = epochTime -> ZonedDateTime.ofInstant(Instant.ofEpochMilli(epochTime), ZoneOffset.UTC);

    private SSLSessionUtils() {}

    public static void invalidateCaches(SSLFactory sslFactory) {
        invalidateServerCaches(sslFactory);
        invalidateClientCaches(sslFactory);
    }

    public static void invalidateServerCaches(SSLFactory sslFactory) {
        invalidateServerCaches(sslFactory.getSslContext());
    }

    public static void invalidateClientCaches(SSLFactory sslFactory) {
        invalidateClientCaches(sslFactory.getSslContext());
    }

    public static void invalidateCaches(SSLContext sslContext) {
        invalidateServerCaches(sslContext);
        invalidateClientCaches(sslContext);
    }

    public static void invalidateServerCaches(SSLContext sslContext) {
        invalidateCaches(sslContext.getServerSessionContext());
    }

    public static void invalidateClientCaches(SSLContext sslContext) {
        invalidateCaches(sslContext.getClientSessionContext());
    }

    public static void invalidateCaches(SSLSessionContext sslSessionContext) {
        SSLSessionUtils.getSslSessions(sslSessionContext).forEach(SSLSession::invalidate);
    }

    public static void invalidateCachesBefore(SSLFactory sslFactory, ZonedDateTime upperBoundary) {
        invalidateCachesBefore(sslFactory.getSslContext(), upperBoundary);
    }

    public static void invalidateCachesBefore(SSLContext sslContext, ZonedDateTime upperBoundary) {
        invalidateCachesBefore(sslContext.getServerSessionContext(), upperBoundary);
        invalidateCachesBefore(sslContext.getClientSessionContext(), upperBoundary);
    }

    public static void invalidateCachesBefore(SSLSessionContext sslSessionContext, ZonedDateTime upperBoundary) {
        invalidateCachesWithTimeStamp(sslSessionContext, sslSessionCreationTime -> sslSessionCreationTime.isBefore(upperBoundary));
    }

    public static void invalidateCachesAfter(SSLFactory sslFactory, ZonedDateTime lowerBoundary) {
        invalidateCachesAfter(sslFactory.getSslContext(), lowerBoundary);
    }

    public static void invalidateCachesAfter(SSLContext sslContext, ZonedDateTime lowerBoundary) {
        invalidateCachesAfter(sslContext.getServerSessionContext(), lowerBoundary);
        invalidateCachesAfter(sslContext.getClientSessionContext(), lowerBoundary);
    }

    public static void invalidateCachesAfter(SSLSessionContext sslSessionContext, ZonedDateTime lowerBoundary) {
        invalidateCachesWithTimeStamp(sslSessionContext, sslSessionCreationTime -> sslSessionCreationTime.isAfter(lowerBoundary));
    }

    public static void invalidateCachesBetween(SSLFactory sslFactory, ZonedDateTime lowerBoundary, ZonedDateTime upperBoundary) {
        invalidateCachesBetween(sslFactory.getSslContext(), lowerBoundary, upperBoundary);
    }

    public static void invalidateCachesBetween(SSLContext sslContext, ZonedDateTime lowerBoundary, ZonedDateTime upperBoundary) {
        invalidateCachesBetween(sslContext.getServerSessionContext(), lowerBoundary, upperBoundary);
        invalidateCachesBetween(sslContext.getClientSessionContext(), lowerBoundary, upperBoundary);
    }

    public static void invalidateCachesBetween(SSLSessionContext sslSessionContext, ZonedDateTime lowerBoundary, ZonedDateTime upperBoundary) {
        Predicate<ZonedDateTime> isAfterLowerBoundary = sslSessionCreationTime -> sslSessionCreationTime.isAfter(lowerBoundary);
        Predicate<ZonedDateTime> isBeforeUpperBoundary = sslSessionCreationTime -> sslSessionCreationTime.isBefore(upperBoundary);

        invalidateCachesWithTimeStamp(sslSessionContext, isAfterLowerBoundary.and(isBeforeUpperBoundary));
    }

    private static void invalidateCachesWithTimeStamp(SSLSessionContext sslSessionContext, Predicate<ZonedDateTime> timeStampPredicate) {
        SSLSessionUtils.getSslSessions(sslSessionContext).stream()
                .filter(sslSession -> timeStampPredicate.test(EPOCH_TIME_MAPPER.apply(sslSession.getCreationTime())))
                .forEach(SSLSession::invalidate);
    }

    public static void updateSessionTimeout(SSLFactory sslFactory, int timeoutInSeconds) {
        updateSessionTimeout(sslFactory.getSslContext(), timeoutInSeconds);
    }

    public static void updateSessionTimeout(SSLContext sslContext, int timeoutInSeconds) {
        validateSessionTimeout(timeoutInSeconds);

        sslContext.getClientSessionContext().setSessionTimeout(timeoutInSeconds);
        sslContext.getServerSessionContext().setSessionTimeout(timeoutInSeconds);
    }

    public static void updateSessionCacheSize(SSLFactory sslFactory, int cacheSizeInBytes) {
        updateSessionCacheSize(sslFactory.getSslContext(), cacheSizeInBytes);
    }

    public static void updateSessionCacheSize(SSLContext sslContext, int cacheSizeInBytes) {
        validateSessionCacheSize(cacheSizeInBytes);

        sslContext.getClientSessionContext().setSessionCacheSize(cacheSizeInBytes);
        sslContext.getServerSessionContext().setSessionCacheSize(cacheSizeInBytes);
    }

    public static void validateSessionTimeout(int timeoutInSeconds) {
        if (timeoutInSeconds < 0) {
            throw new IllegalArgumentException(String.format(
                    "Unsupported timeout has been provided. Timeout should be equal or greater than [%d], but received [%d]",
                    0, timeoutInSeconds));
        }
    }

    public static void validateSessionCacheSize(int cacheSizeInBytes) {
        if (cacheSizeInBytes < 0) {
            throw new IllegalArgumentException(String.format(
                    "Unsupported cache size has been provided. Cache size should be equal or greater than [%d], but received [%d]",
                    0, cacheSizeInBytes));
        }
    }

    public static List<SSLSession> getServerSslSessions(SSLFactory sslFactory) {
        return getServerSslSessions(sslFactory.getSslContext());
    }

    public static List<SSLSession> getServerSslSessions(SSLContext sslContext) {
        return getSslSessions(sslContext.getServerSessionContext());
    }

    public static List<SSLSession> getClientSslSessions(SSLFactory sslFactory) {
        return getClientSslSessions(sslFactory.getSslContext());
    }

    public static List<SSLSession> getClientSslSessions(SSLContext sslContext) {
        return getSslSessions(sslContext.getClientSessionContext());
    }

    public static List<SSLSession> getSslSessions(SSLSessionContext sslSessionContext) {
        return Collections.list(sslSessionContext.getIds()).stream()
                .map(sslSessionContext::getSession)
                .filter(Objects::nonNull)
                .collect(toUnmodifiableList());
    }

}
