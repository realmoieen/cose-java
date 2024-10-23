/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author jimsch
 */
public class Encrypt0MessageTest extends TestBase {
    byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};
    byte[] rgbIV128 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte[] rgbIV96 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    public Encrypt0MessageTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        Encrypt0Message msg = new Encrypt0Message();
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        byte[] rgbMsg = msg.EncodeToBytes();

        msg = (Encrypt0Message) Message.DecodeFromBytes(rgbMsg, MessageTag.Encrypt0);
        byte[] contentNew = msg.decrypt(rgbKey128);

        assertArrayEquals(rgbContent, contentNew);
    }

    @Test
    public void encryptNoAlgorithm() {
        Encrypt0Message msg = new Encrypt0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.SetContent(rgbContent);
                    msg.encrypt(rgbKey128);
                });
        assertEquals("No Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void encryptUnknownAlgorithm() {
        Encrypt0Message msg = new Encrypt0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt(rgbKey128);
                });
        assertEquals("Unknown Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void encryptUnsupportedAlgorithm() {
        Encrypt0Message msg = new Encrypt0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt(rgbKey128);
                });
        assertEquals("Unsupported Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void encryptIncorrectKeySize() {
        Encrypt0Message msg = new Encrypt0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt(rgbKey256);
                });
        assertEquals("Key Size is incorrect", thrown.getMessage());
    }

    @Test
    public void encryptNullKey() {
        Encrypt0Message msg = new Encrypt0Message();

        assertThrows(NullPointerException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt(null);
                });
    }

    @Test
    public void encryptNoContent() {
        Encrypt0Message msg = new Encrypt0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.encrypt(rgbKey128);
                });
        assertEquals("No Content Specified", thrown.getMessage());
    }

    @Test
    public void encryptBadIV() {
        Encrypt0Message msg = new Encrypt0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), Attribute.UNPROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt(rgbKey128);
                });
        assertEquals("IV is incorrectly formed", thrown.getMessage());
    }

    @Test
    public void encryptIncorrectIV() {
        Encrypt0Message msg = new Encrypt0Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.addAttribute(HeaderKeys.IV, rgbIV128, Attribute.UNPROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt(rgbKey128);
                });
        assertEquals("IV size is incorrect", thrown.getMessage());
    }

    @Test
    public void encryptNoTag() throws CoseException {
        Encrypt0Message msg = new Encrypt0Message(false, true);

        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        CBORObject cn = msg.EncodeCBORObject();

        assert (!cn.isTagged());
    }

    @Test
    public void encryptNoEmitContent() throws CoseException {
        Encrypt0Message msg = new Encrypt0Message(true, false);

        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.UNPROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        CBORObject cn = msg.EncodeCBORObject();

        assert (cn.get(2).isNull());
    }

    @Test
    public void noContentForDecrypt() throws IllegalStateException {

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    Encrypt0Message msg = new Encrypt0Message(true, false);
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
                    msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.UNPROTECTED);
                    msg.SetContent(rgbContent);
                    msg.encrypt(rgbKey128);

                    byte[] rgb = msg.EncodeToBytes();

                    msg = (Encrypt0Message) Message.DecodeFromBytes(rgb);
                    msg.decrypt(rgbKey128);
                });
        assertEquals("No Encrypted Content Specified", thrown.getMessage());

    }

    @Test
    public void roundTripDetached() throws CoseException, IllegalStateException {
        Encrypt0Message msg = new Encrypt0Message(true, false);

        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.UNPROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);

        byte[] content = msg.getEncryptedContent();

        byte[] rgb = msg.EncodeToBytes();

        msg = (Encrypt0Message) Message.DecodeFromBytes(rgb);
        msg.setEncryptedContent(content);
        msg.decrypt(rgbKey128);

    }

    @Test
    public void encryptWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);
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
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);
                });
        assertEquals("Invalid Encrypt0 structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadProtected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);
                });
        assertEquals("Invalid Encrypt0 structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadProtected2() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);
                });
        assertEquals("Invalid Encrypt0 structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadUnprotected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);
                });
        assertEquals("Invalid Encrypt0 structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadContent() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);
                });
        assertEquals("Invalid Encrypt0 structure", thrown.getMessage());
    }

    @Test
    public void encryptDecodeBadTag() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);
                });
        assertEquals("Invalid Encrypt0 structure", thrown.getMessage());
    }
}
