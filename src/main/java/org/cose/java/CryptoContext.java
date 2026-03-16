package org.cose.java;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Provides configuration for selecting the JCA {@link Provider} used for
 * cryptographic operations such as signing and verifying COSE messages.
 * <p>
 * By default, this class uses the Bouncy Castle provider
 * ({@code "BC"}) if it is registered in the JVM's security providers list.
 * This ensures backward compatibility with existing implementations that rely
 * on Bouncy Castle for COSE operations.
 * <p>
 * The {@code CryptoContext} allows applications to:
 * <ul>
 *     <li>Override the default provider globally using
 *     {@link #setDefaultProvider(Provider)}</li>
 *     <li>Specify a provider instance per context using
 *     {@link #setProvider(Provider)}</li>
 *     <li>Set the provider to {@code null} to let the JVM's
 *     {@linkplain java.security.Signature#getInstance(String) default provider
 *     selection mechanism} pick the appropriate provider based on the key type
 *     (useful for PKCS#11, HSMs, and cloud-based providers)</li>
 * </ul>
 * <p>
 * Thread-safety note: Updating the default provider is synchronized to prevent
 * inconsistent state, but instance-level provider changes are not
 * synchronized and should be handled by callers if used across threads.
 */
public abstract class CryptoContext {

    private static Provider defaultProvider =
            Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

    private Provider provider = defaultProvider;

    /**
     * Returns the currently configured global default {@link Provider}.
     * <p>
     * This provider will be used for all {@code CryptoContext} instances
     * unless explicitly overridden via {@link #setProvider(Provider)}.
     *
     * @return the default JCA provider, or {@code null} if none is configured
     */
    public static Provider getDefaultProvider() {
        return defaultProvider;
    }

    /**
     * Sets the global default JCA {@link Provider} used by new
     * {@code CryptoContext} instances unless they override it individually.
     * <p>
     * Passing {@code null} allows the JVM to automatically determine the
     * appropriate provider for cryptographic operations.
     *
     * @param provider the provider to set as the default, or {@code null}
     */
    public static void setDefaultProvider(Provider provider) {
        synchronized (CryptoContext.class) {
            defaultProvider = provider;
        }
    }

    /**
     * Returns the specific JCA {@link Provider} configured for this context.
     * <p>
     * If no custom provider has been set, this returns the global default
     * provider, which is Bouncy Castle by default.
     *
     * @return the provider used by this instance, or {@code null} if JVM
     * provider auto-selection should be used
     */
    public Provider getProvider() {
        return provider;
    }

    /**
     * Sets the JCA {@link Provider} for this specific cryptographic context.
     * <p>
     * Passing {@code null} allows the JVM's internal provider selection
     * mechanism to choose the correct provider based on the key type,
     * ensuring compatibility with PKCS#11, HSM-backed, and cloud-hosted keys.
     *
     * @param provider the provider to use for this context, or {@code null}
     */
    public void setProvider(Provider provider) {
        this.provider = provider;
    }
}