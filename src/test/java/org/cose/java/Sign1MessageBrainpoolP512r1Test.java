/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;

/**
 * @author jimsch
 */
@Disabled
public class Sign1MessageBrainpoolP512r1Test extends AbstractSign1MessageTest {

    @BeforeAll
    public static void setUpClass() throws CoseException {
        x9ECParameters = ECNamedCurveTable.getByName("brainpoolp512r1");
        curve = KeyKeys.EC2_BP512R1;
        signingAlgorithm = AlgorithmID.ECDSA_256.AsCBOR();
        setUpClassForEC();
    }
}
