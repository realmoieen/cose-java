/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import com.upokecenter.cbor.CBORObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author jimsch
 */
@Slf4j
public class MessageTest extends TestBase {
    byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    byte[] rgbContent = new byte[]{1,2,3,4,5,6,7};
    byte[] rgbIV96 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    public MessageTest() {
    }

    /**
     * Test of DecodeFromBytes method, of class Message.
     */
    @Test
    public void testDecodeUnknown() throws Exception {
        Encrypt0Message msg = new Encrypt0Message(false, true);
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        byte[] rgbMsg = msg.EncodeToBytes();
        
        CoseException thrown = assertThrows(CoseException.class,
                () -> Message.DecodeFromBytes(rgbMsg, MessageTag.Unknown));
        assertEquals("Message was not tagged and no default tagging option given", thrown.getMessage());
    }

    /**
     * Test of DecodeFromBytes method, of class Message.
     */
    @Test
    public void testDecodeFromBytes_byteArr_MessageTag() throws Exception {
        Encrypt0Message msg = new Encrypt0Message(true, false);
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        byte[] rgbMsg = msg.EncodeToBytes();
        
        msg = (Encrypt0Message) Message.DecodeFromBytes(rgbMsg);
        assertFalse(msg.HasContent());
    }

    /**
     * Test of HasContent method, of class Message.
     */
    @Test
    public void testHasContent() {
        log.debug("HasContent");
        Message instance = new Encrypt0Message();
        boolean expResult = false;
        boolean result = instance.HasContent();
        assertEquals(expResult, result);
        
        instance.SetContent(new byte[10]);
        result = instance.HasContent();
        assertTrue(result);
    }

    /**
     * Test of SetContent method, of class Message.
     */
    @Test
    public void testSetContent_byteArr() {
        log.debug("SetContent");
        byte[] rgbData = new byte[]{1,2,3,4,5,6,7};
        Message instance = new Encrypt0Message();
        instance.SetContent(rgbData);
        
        byte[] result = instance.GetContent();
        assertArrayEquals(result, rgbData);
    }

    /**
     * Test of SetContent method, of class Message.
     */
    @Test
    public void testSetContent_String() {
        log.debug("SetContent");
        String strData = "12345678";
        byte[] rgbData = new byte[]{49, 50, 51, 52, 53, 54, 55, 56};
        
        Message instance = new Encrypt0Message();
        instance.SetContent(strData);
        byte[] result = instance.GetContent();
        assertArrayEquals(result, rgbData);
    }    
}
