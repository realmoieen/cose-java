/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.augustcellars.cose;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.junit.jupiter.api.BeforeAll;

/**
 * @author jimsch
 */
public class Sign1MessageNISTP256Test extends AbstractSign1MessageTest {

    @BeforeAll
    public static void setUpClass() throws CoseException {
        x9ECParameters = NISTNamedCurves.getByName("P-256");
        curve = KeyKeys.EC2_P256;
        signingAlgorithm = AlgorithmID.ECDSA_256.AsCBOR();
        setUpClassForEC();
    }
}
