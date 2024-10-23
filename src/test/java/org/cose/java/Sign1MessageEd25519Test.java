/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import org.junit.jupiter.api.BeforeAll;

/**
 * @author jimsch
 */
public class Sign1MessageEd25519Test extends AbstractSign1MessageTest {

    @BeforeAll
    public static void setUpClass() throws CoseException {
        setUpClassForED25519();
    }
}
