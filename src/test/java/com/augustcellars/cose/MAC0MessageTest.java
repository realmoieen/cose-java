/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.augustcellars.cose;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author jimsch
 */
public class MAC0MessageTest extends TestBase {
    //static byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    static byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};

    CBORObject cnKey256;


    @BeforeEach
    public void setUp() {
        cnKey256 = CBORObject.NewMap();
        cnKey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        cnKey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(rgbKey256));
    }

    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */

    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        MAC0Message msg = new MAC0Message();
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.Create(rgbKey256);

        byte[] rgbMsg = msg.EncodeToBytes();

        msg = (MAC0Message) Message.DecodeFromBytes(rgbMsg, MessageTag.MAC0);
        boolean contentNew = msg.Validate(rgbKey256);
        assertTrue(contentNew);
    }

    @Test
    public void macNoAlgorithm() {
        MAC0Message msg = new MAC0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.SetContent(rgbContent);
                    msg.Create(rgbKey256);
                });
        assertEquals("No Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void macUnknownAlgorithm() {
        MAC0Message msg = new MAC0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.Create(rgbKey256);
                });
        assertEquals("Unknown Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void macUnsupportedAlgorithm() {
        MAC0Message msg = new MAC0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_256.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.Create(rgbKey256);
                });
        assertEquals("Unsupported MAC Algorithm", thrown.getMessage());
    }

    @Test
    public void macNoContent() {
        MAC0Message msg = new MAC0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
                    msg.Create(rgbKey256);
                });
        assertEquals("No Content Specified", thrown.getMessage());
    }

    @Test
    public void macDecodeWrongBasis() {
        CBORObject obj = CBORObject.NewMap();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.MAC0);
                });
        assertEquals("Message is not a COSE security Message", thrown.getMessage());

    }

    @Test
    public void macDecodeWrongCount() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.MAC0);
                });
        assertEquals("Invalid MAC0 structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadProtected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.MAC0);
                });
        assertEquals("Invalid MAC0 structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadProtected2() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.MAC0);
                });
        assertEquals("Invalid MAC0 structure", thrown.getMessage());

    }

    @Test
    public void macDecodeBadUnprotected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.MAC0);
                });
        assertEquals("Invalid MAC0 structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadContent() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.MAC0);
                });
        assertEquals("Invalid MAC0 structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadRecipients() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.MAC0);
                });
        assertEquals("Invalid MAC0 structure", thrown.getMessage());
    }

}
