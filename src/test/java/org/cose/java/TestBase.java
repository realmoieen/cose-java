/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 *
 * @author linuxwolf
 */
public abstract class TestBase {
    private static final Provider    PROVIDER = new BouncyCastleProvider();
//    private static final Provider    EdDSA = new EdDSASecurityProvider();

    @BeforeAll
    public static void installProvider() throws Exception {
        Security.insertProviderAt(PROVIDER, 0);
  //      Security.insertProviderAt(EdDSA, 0);
    }
    @AfterAll
    public static void uninstallProvider() throws Exception {
        Security.removeProvider(PROVIDER.getName());
   //     Security.removeProvider(EdDSA.getName());
    }
}
