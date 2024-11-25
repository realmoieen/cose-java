/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import com.upokecenter.cbor.CBORObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;


/**
 * @author jimsch
 */
@Slf4j
public class SignMessageTest extends TestBase {

    /**
     * Test of EncodeCBORObject method, of class SignMessage.
     */
    @Disabled
    @Test
    public void testEncodeCBORObject() throws Exception {
        log.debug("EncodeCBORObject");
        SignMessage instance = new SignMessage();
        CBORObject expResult = null;
        CBORObject result = instance.EncodeCBORObject();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getSigner method, of class SignMessage.
     */
    @Disabled
    @Test
    public void testGetSigner() {
        log.debug("getSigner");
        int iSigner = 0;
        SignMessage instance = new SignMessage();
        Signer expResult = null;
        Signer result = instance.getSigner(iSigner);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    @Test
    public void testGetSignerCount() {
        SignMessage msg = new SignMessage();

        assertEquals(msg.getSignerCount(), 0);

        Signer r = new Signer();
        msg.AddSigner(r);
        assertEquals(msg.getSignerCount(), 1);
    }

    /**
     * Test of sign method, of class SignMessage.
     */
    @Disabled
    @Test
    public void testSign() throws CoseException {
        log.debug("sign");
        SignMessage instance = new SignMessage();
        instance.sign();
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of validate method, of class SignMessage.
     */
    @Disabled
    @Test
    public void testValidate() throws CoseException {
        log.debug("validate");
        Signer signerToUse = null;
        SignMessage instance = new SignMessage();
        boolean expResult = false;
        boolean result = instance.validate(signerToUse);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    @Test
    public void signDecodeWrongBasis() {
        CBORObject obj = CBORObject.NewMap();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign);
                });
        assertEquals("Message is not a COSE security Message", thrown.getMessage());
    }

    @Test
    public void signDecodeWrongCount() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign);
                });
        assertEquals("Invalid SignMessage structure", thrown.getMessage());
    }

    @Test
    public void signDecodeBadProtected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign);
                });
        assertEquals("Invalid SignMessage structure", thrown.getMessage());
    }

    @Test
    public void signDecodeBadProtected2() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign);
                });
        assertEquals("Invalid SignMessage structure", thrown.getMessage());
    }

    @Test
    public void signDecodeBadUnprotected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign);
                });
        assertEquals("Invalid SignMessage structure", thrown.getMessage());
    }

    @Test
    public void signDecodeBadContent() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign);
                });
        assertEquals("Invalid SignMessage structure", thrown.getMessage());
    }

    @Test
    public void signDecodeBadRecipients() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign);
                });
        assertEquals("Invalid SignMessage structure", thrown.getMessage());
    }

}
