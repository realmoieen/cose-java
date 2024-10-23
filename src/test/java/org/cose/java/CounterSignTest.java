/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author jimsch
 */
public class CounterSignTest extends TestBase {

    @Test
    public void signerDecodeWrongBasis() {
        CBORObject obj = CBORObject.NewMap();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    CounterSign sig = new CounterSign();
                    sig.DecodeFromBytes(rgb);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());
    }

    @Test
    public void signerDecodeWrongCount() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    CounterSign sig = new CounterSign();
                    sig.DecodeFromBytes(rgb);
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

                    byte[] rgb = obj.EncodeToBytes();
                    CounterSign sig = new CounterSign();
                    sig.DecodeFromBytes(rgb);
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

                    byte[] rgb = obj.EncodeToBytes();
                    CounterSign sig = new CounterSign();
                    sig.DecodeFromBytes(rgb);
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

                    byte[] rgb = obj.EncodeToBytes();
                    CounterSign sig = new CounterSign();
                    sig.DecodeFromBytes(rgb);
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

                    byte[] rgb = obj.EncodeToBytes();
                    CounterSign sig = new CounterSign();
                    sig.DecodeFromBytes(rgb);
                });
        assertEquals("Invalid Signer structure", thrown.getMessage());
    }

}
