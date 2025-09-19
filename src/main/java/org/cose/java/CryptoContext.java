package org.cose.java;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Specify which JCA Provider to use for signing and verifying messages. with Bouncy castle as default provider. make sure Bouncy castle is registered as provider
 */
public class CryptoContext {

    private Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

    public CryptoContext() {

    }

    public CryptoContext(Provider provider) {
        this.provider = provider;
    }

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider;
    }

}