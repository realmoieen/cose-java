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
public class MACMessageTest extends TestBase {
    static byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    static byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};

    Recipient recipient256;
    OneKey cnKey256;

    public MACMessageTest() {
    }


    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() throws CoseException {
        recipient256 = new Recipient();
        recipient256.addAttribute(HeaderKeys.Algorithm, AlgorithmID.Direct.AsCBOR(), Attribute.UNPROTECTED);
        CBORObject key256 = CBORObject.NewMap();
        key256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        key256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(rgbKey256));
        cnKey256 = new OneKey(key256);
        recipient256.SetKey(cnKey256);
    }

    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of addRecipient method, of class MACMessage.
     */
    @Test
    public void testAddRecipient() throws CoseException {
        System.out.println("addRecipient");
        Recipient recipient = null;
        MACMessage instance = new MACMessage();

        CoseException thrown = assertThrows(CoseException.class,
                () -> instance.addRecipient(recipient));
        assertEquals("Recipient is null", thrown.getMessage());
    }

    /**
     * Test of getRecipient method, of class MACMessage.
     */
    @Test
    public void testGetRecipient_1args_1() throws CoseException {
        System.out.println("getRecipient");
        int iRecipient = 0;
        MACMessage instance = new MACMessage();
        Recipient expResult = new Recipient();
        instance.addRecipient(expResult);
        Recipient result = instance.getRecipient(iRecipient);
        assertEquals(expResult, result);
    }

    @Test
    public void testGetRecipientCount() throws CoseException {
        MACMessage msg = new MACMessage();

        assertEquals(msg.getRecipientCount(), 0);

        Recipient r = new Recipient();
        msg.addRecipient(r);
        assertEquals(msg.getRecipientCount(), 1);
    }

    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        MACMessage msg = new MACMessage();
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.addRecipient(recipient256);
        msg.Create();

        byte[] rgbMsg = msg.EncodeToBytes();

        msg = (MACMessage) Message.DecodeFromBytes(rgbMsg, MessageTag.MAC);
        Recipient r = msg.getRecipient(0);
        r.SetKey(cnKey256);
        boolean contentNew = msg.Validate(r);
        assertTrue(contentNew);
    }

    @Test
    public void macNoRecipients() {
        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    MACMessage msg = new MACMessage();
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.Create();
                });
        assertEquals("No recipients supplied", thrown.getMessage());
    }

    @Test
    public void macNoAlgorithm() throws CoseException, Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.SetContent(rgbContent);
                    msg.Create();
                });
        assertEquals("No Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void macUnknownAlgorithm() throws Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.Create();
                });
        assertEquals("Unknown Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void macUnsupportedAlgorithm() throws CoseException, Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_256.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.Create();
                });
        assertEquals("Unsupported MAC Algorithm", thrown.getMessage());
    }

    @Test
    public void macNoContent() throws Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
                    msg.Create();
                });
        assertEquals("No Content Specified", thrown.getMessage());
    }

    @Test
    public void macDecodeWrongBasis() {
        CBORObject obj = CBORObject.NewMap();


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
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
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
                });
        assertEquals("Invalid MAC structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadProtected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
                });
        assertEquals("Invalid MAC structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadProtected2() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
                });
        assertEquals("Invalid MAC structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadUnprotected() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
                });
        assertEquals("Invalid MAC structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadContent() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
                });
        assertEquals("Invalid MAC structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadTag() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.FromObject(rgbContent));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
                });
        assertEquals("Invalid MAC structure", thrown.getMessage());
    }

    @Test
    public void macDecodeBadRecipients() {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.FromObject(rgbContent));
        obj.Add(CBORObject.FromObject(rgbContent));
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {

                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);
                });
        assertEquals("Invalid MAC structure", thrown.getMessage());
    }
}
