/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import com.upokecenter.cbor.*;

import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author jimsch
 */
@Slf4j
public class EncryptMessageTest extends TestBase {
    static byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    static byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};
    static byte[] rgbIV128 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    static byte[] rgbIV96 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    Recipient recipient128;
    OneKey cnKey128;

    @BeforeEach
    public void setUp() throws CoseException {
        recipient128 = new Recipient();
        recipient128.addAttribute(HeaderKeys.Algorithm, AlgorithmID.Direct.AsCBOR(), Attribute.UNPROTECTED);
        CBORObject key128 = CBORObject.NewMap();
        key128.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        key128.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(rgbKey128));
        cnKey128 = new OneKey(key128);
        recipient128.SetKey(cnKey128);
    }

    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTrip() throws Exception {
        log.debug("Round Trip");
        EncryptMessage msg = new EncryptMessage();
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.addRecipient(recipient128);
        msg.encrypt();

        List<Recipient> rList = msg.getRecipientList();
        assertEquals(rList.size(), 1);

        byte[] rgbMsg = msg.EncodeToBytes();

        msg = (EncryptMessage) Message.DecodeFromBytes(rgbMsg, MessageTag.Encrypt);
        Recipient r = msg.getRecipient(0);
        r.SetKey(cnKey128);
        byte[] contentNew = msg.decrypt(r);


        assertArrayEquals(rgbContent, contentNew);
    }

    @Test
    public void testGetRecipientCount() {
        EncryptMessage msg = new EncryptMessage();

        assertEquals(msg.getRecipientCount(), 0);

        Recipient r = new Recipient();
        msg.addRecipient(r);
        assertEquals(msg.getRecipientCount(), 1);
    }

    @Test
    public void encryptNoRecipients() {
        EncryptMessage msg = new EncryptMessage();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt();
                });
        assertEquals("No recipients supplied", thrown.getMessage());
    }

    @Test
    public void encryptNoAlgorithm() {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.SetContent(rgbContent);
                    msg.encrypt();
                });
        assertEquals("No Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void encryptUnknownAlgorithm() {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt();
                });
        assertEquals("Unknown Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void encryptUnsupportedAlgorithm() {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt();
                });
        assertEquals("Unsupported Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void encryptNoContent() {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.encrypt();
                });
        assertEquals("No Content Specified", thrown.getMessage());
    }

    @Test
    public void encryptBadIV() {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), Attribute.UNPROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt();
                });
        assertEquals("IV is incorrectly formed", thrown.getMessage());
    }

    @Test
    public void encryptIncorrectIV() {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.addAttribute(HeaderKeys.IV, rgbIV128, Attribute.UNPROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt();
                });
        assertEquals("IV size is incorrect", thrown.getMessage());
    }

    @Test
    public void encryptDecodeWrongBasis() {
        CBORObject obj = CBORObject.NewMap();


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt);
                });
        assertEquals("Message is not a COSE security Message", thrown.getMessage());
    }

    @Test
    public void encryptDecodeWrongCount() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt);
                });
        assertEquals("Invalid Encrypt structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt);
                });
        assertEquals("Invalid Encrypt structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadProtected2() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt);
                });
        assertEquals("Invalid Encrypt structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadUnprotected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt);
                });
        assertEquals("Invalid Encrypt structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadContent() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt);
                });
        assertEquals("Invalid Encrypt structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadRecipients() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt);
                });
        assertEquals("Invalid Encrypt structure", thrown.getMessage());
    }
}
