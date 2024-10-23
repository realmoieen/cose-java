/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author jimsch
 */
public class Sign1WikiTest extends TestBase {
    static OneKey signingKey;
    static OneKey sign2Key;
    static OneKey sign3Key;
    
    @BeforeEach
    public void setUp() throws CoseException {
        signingKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        sign2Key = OneKey.generateKey(AlgorithmID.ECDSA_512);
        sign3Key = OneKey.generateKey(AlgorithmID.ECDSA_384);
    }
    
    @Test
    public void testSignAMessage() throws CoseException {
        byte[] result = SignAMessage("This is lots of content");
        assert( VerifyAMessage(result, signingKey) );
        assert( !VerifyAMessage(result, sign2Key));
    }
    
    public static byte[] SignAMessage(String ContentToSign) throws CoseException {
        
    //  Create the signed message
    Sign1Message msg = new Sign1Message();
    
    //  Add the content to the message
    msg.SetContent(ContentToSign);
    msg.addAttribute(HeaderKeys.Algorithm, signingKey.get(KeyKeys.Algorithm), Attribute.PROTECTED);
    
    //  Force the message to be signed
    msg.sign(signingKey);

    //  Now serialize out the message
    return msg.EncodeToBytes();
    }
    
    public static boolean VerifyAMessage(byte[] message, OneKey key) {
        boolean result;
        
        try {
            Sign1Message msg = (Sign1Message) Message.DecodeFromBytes(message);
          
            result = msg.validate(key);
        } catch (CoseException e) {
            return false;
        }
        
        return result;
    }
}
