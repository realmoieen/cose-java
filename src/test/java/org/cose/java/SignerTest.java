/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author jimsch
 */
public class SignerTest extends TestBase {

    /**
     * Test of setKey method, of class Signer.
     */
    @Disabled
    @Test
    public void testSetKey() throws CoseException {
        System.out.println("setKey");
        OneKey cnKey = null;
        Signer instance = new Signer();
        instance.setKey(cnKey);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    @Test
    public void signerDecodeWrongBasis() {
        CBORObject obj = CBORObject.NewMap();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    Signer sig = new Signer();
                    sig.DecodeFromCBORObject(obj);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());
    }

    @Test
    public void signerDecodeWrongCount() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    Signer sig = new Signer();
                    sig.DecodeFromCBORObject(obj);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());

    }

    @Test
    public void signerDecodeBadProtected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    Signer sig = new Signer();
                    sig.DecodeFromCBORObject(obj);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());
    }

    @Test
    public void signerDecodeBadProtected2() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    Signer sig = new Signer();
                    sig.DecodeFromCBORObject(obj);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());
    }

    @Test
    public void signerDecodeBadUnprotected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    Signer sig = new Signer();
                    sig.DecodeFromCBORObject(obj);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());
    }

    @Test
    public void signerDecodeBadSignature() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    Signer sig = new Signer();
                    sig.DecodeFromCBORObject(obj);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());
    }
}
