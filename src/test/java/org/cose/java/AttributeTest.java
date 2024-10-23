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
 *
 * @author jimsch
 */
public class AttributeTest extends TestBase {
    
    @Test
    public void testAddAttribute_1() {
        CBORObject label = CBORObject.FromObject(new byte[1]);
        CBORObject value = null;
        int where = Attribute.PROTECTED;
        Attribute instance = new Attribute();

        CoseException thrown = assertThrows(CoseException.class,
                () -> instance.addAttribute(label, value, where));

        assertEquals("Labels must be integers or strings", thrown.getMessage());
    }

    @Test
    public void testAddAttribute_2() throws Exception {
        CBORObject label = CBORObject.FromObject(1);
        CBORObject value = CBORObject.FromObject(2);
        int where = 0;
        Attribute instance = new Attribute();

        CoseException thrown = assertThrows(CoseException.class,
                () -> instance.addAttribute(label, value, where));

        assertEquals("Invalid attribute location given", thrown.getMessage());
    }

    @Test
    public void testAddAttribute_3() throws Exception {
        byte[] rgbKey = new byte[256/8];
        MAC0Message msg = new MAC0Message();
        msg.SetContent("ABCDE");
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
        msg.Create(rgbKey);

        CoseException thrown = assertThrows(CoseException.class,
                () -> msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED));

        assertEquals("Operation would modify integrity protected attributes", thrown.getMessage());
    }
    
    @Test
    public void testAddAttribute_4() throws Exception {
        Attribute instance = new Attribute();
        
        instance.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CBC_MAC_128_128.AsCBOR(), Attribute.PROTECTED);
        instance.addAttribute(HeaderKeys.CONTENT_TYPE, AlgorithmID.AES_CBC_MAC_128_64.AsCBOR(), Attribute.UNPROTECTED);
        instance.addAttribute(HeaderKeys.CounterSignature, AlgorithmID.AES_CBC_MAC_256_64.AsCBOR(), Attribute.DO_NOT_SEND);
        
        CBORObject cn;
        
        cn = instance.findAttribute(HeaderKeys.Algorithm, Attribute.PROTECTED);
        assertSame(cn, AlgorithmID.AES_CBC_MAC_128_128.AsCBOR());
        assert(null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.UNPROTECTED));
        assert(null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.DO_NOT_SEND));
        
        cn = instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.UNPROTECTED);
        assertSame(cn, AlgorithmID.AES_CBC_MAC_128_64.AsCBOR());
        assert(null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.PROTECTED));
        assert(null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.DO_NOT_SEND));

        cn = instance.findAttribute(HeaderKeys.CounterSignature, Attribute.DO_NOT_SEND);
        assertSame(cn, AlgorithmID.AES_CBC_MAC_256_64.AsCBOR());
        assert(null == instance.findAttribute(HeaderKeys.CounterSignature, Attribute.UNPROTECTED));
        assert(null == instance.findAttribute(HeaderKeys.CounterSignature, Attribute.PROTECTED));
    }
    
    @Test
    public void testAddAttribute_5() throws Exception {
        Attribute instance = new Attribute();
        
        instance.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CBC_MAC_128_128.AsCBOR(), Attribute.PROTECTED);
        instance.addAttribute(HeaderKeys.CONTENT_TYPE, AlgorithmID.AES_CBC_MAC_128_64.AsCBOR(), Attribute.UNPROTECTED);

        instance.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.PROTECTED);
        instance.addAttribute(HeaderKeys.CONTENT_TYPE, AlgorithmID.ECDH_ES_HKDF_256.AsCBOR(), Attribute.PROTECTED);

        CBORObject cn;
        
        cn = instance.findAttribute(HeaderKeys.Algorithm, Attribute.PROTECTED);
        assertSame(cn, AlgorithmID.ECDSA_256.AsCBOR());
        assert(null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.UNPROTECTED));
        assert(null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.DO_NOT_SEND));

        cn = instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.PROTECTED);
        assertSame(cn, AlgorithmID.ECDH_ES_HKDF_256.AsCBOR());
        assert(null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.UNPROTECTED));
        assert(null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.DO_NOT_SEND));
    }
    
    @Test
    public void removeAttribute() throws Exception {
        Attribute instance = new Attribute();
        
        instance.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CBC_MAC_128_128.AsCBOR(), Attribute.PROTECTED);
        
        CBORObject cn;
        cn = instance.findAttribute(HeaderKeys.Algorithm);
        assertSame(cn, AlgorithmID.AES_CBC_MAC_128_128.AsCBOR());
        
        instance.removeAttribute(HeaderKeys.Algorithm);
        cn = instance.findAttribute(HeaderKeys.Algorithm);
        assert(cn == null);
    }
}
