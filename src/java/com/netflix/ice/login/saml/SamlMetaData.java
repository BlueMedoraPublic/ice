/*
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
package com.netflix.ice.login.saml;

import com.netflix.ice.login.*;
import com.netflix.ice.common.IceOptions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;
import java.io.File;
import java.net.URL;
import java.io.StringWriter;
import java.io.IOException;

import org.pac4j.core.client.BaseClient;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;
import org.opensaml.saml.common.xml.SAMLConstants;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML MetaData Plugin.  Provides MetaData for idPs
 */
public class SamlMetaData extends LoginMethod {

    public final String SAML_PREFIX=propertyPrefix("saml");
    Logger logger = LoggerFactory.getLogger(getClass());

    private final SamlConfig config;
    private final SAML2Client client;

    public String propertyName(String name) {
        return SAML_PREFIX + "." + name;
    }

    public SamlMetaData(Properties properties) throws LoginMethodException {
        super(properties);
        config = new SamlConfig(properties);
        SAML2ClientConfiguration client_config = new SAML2ClientConfiguration();

        if (config.serviceIdentifier != null) {
            client_config.setServiceProviderEntityId(config.serviceIdentifier);
        }
        client_config.setIdentityProviderMetadataPath(config.idpMetadataPath);
        client_config.setKeystorePath(config.keystore);
        client_config.setKeystorePassword(config.keystorePassword);
        client_config.setPrivateKeyPassword(config.keyPassword);

        client = new SAML2Client(client_config);
        client.setCallbackUrl(config.signInUrl);
    }

    public LoginResponse processLogin(HttpServletRequest request, HttpServletResponse response) throws LoginMethodException {
        LoginResponse lr = new LoginResponse();
        lr.renderData = client.getIdentityProviderMetadataResolver().getMetadata();
;
        lr.contentType = "application/samlmetadata+xml";
        return lr;
    }
} 

