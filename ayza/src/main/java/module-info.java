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
module nl.altindag.ssl {

    requires transitive nl.altindag.yaslf4j;

    exports nl.altindag.ssl;
    exports nl.altindag.ssl.exception;
    exports nl.altindag.ssl.model;
    exports nl.altindag.ssl.trustmanager.trustoptions;
    exports nl.altindag.ssl.util;
    exports nl.altindag.ssl.sslcontext to java.base;
    exports nl.altindag.ssl.util.internal to nl.altindag.ssl.pem;

}