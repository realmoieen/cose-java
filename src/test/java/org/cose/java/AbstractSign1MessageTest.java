/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.cose.java;

import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author jimsch
 */
public abstract class AbstractSign1MessageTest extends TestBase {

    static byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};

    static OneKey cnKeyPublic;
    static OneKey cnKeyPublicCompressed;
    static OneKey cnKeyPrivate;
    static ECPublicKeyParameters keyPublic;
    static ECPrivateKeyParameters keyPrivate;

    static X9ECParameters x9ECParameters;
    static CBORObject curve;

    static CBORObject signingAlgorithm;

    public static void setUpClassForEC() throws CoseException {

        assert (x9ECParameters != null);
        assert (curve != null);
        assert (signingAlgorithm != null);

        ECDomainParameters parameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH());
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, null);
        pGen.init(genParam);

        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();

        keyPublic = (ECPublicKeyParameters) p1.getPublic();
        keyPrivate = (ECPrivateKeyParameters) p1.getPrivate();

        byte[] rgbX = keyPublic.getQ().normalize().getXCoord().getEncoded();
        byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();
        boolean signY = true;
        byte[] rgbD = keyPrivate.getD().toByteArray();

        CBORObject key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        key.Add(KeyKeys.EC2_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        key.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        cnKeyPublic = new OneKey(key);

        key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        key.Add(KeyKeys.EC2_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        key.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        cnKeyPublicCompressed = new OneKey(key);

        key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        key.Add(KeyKeys.EC2_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.EC2_D.AsCBOR(), rgbD);
        cnKeyPrivate = new OneKey(key);
    }

    public static void setUpClassForED25519() throws CoseException {

        curve = KeyKeys.OKP_Ed25519;
        signingAlgorithm = AlgorithmID.EDDSA.AsCBOR();

        Ed25519KeyPairGenerator pGen = new Ed25519KeyPairGenerator();
        Ed25519KeyGenerationParameters genParam = new Ed25519KeyGenerationParameters(null);
        pGen.init(genParam);

        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();

        Ed25519PublicKeyParameters keyPublic = (Ed25519PublicKeyParameters) p1.getPublic();
        Ed25519PrivateKeyParameters keyPrivate = (Ed25519PrivateKeyParameters) p1.getPrivate();

        byte[] rgbX = keyPublic.getEncoded();//keyPublic.normalize().getXCoord().getEncoded();
        //byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();
        //boolean signY = true;
        byte[] rgbD = keyPrivate.getEncoded();//keyPrivate.getD().toByteArray();

        CBORObject key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        key.Add(KeyKeys.OKP_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.OKP_X.AsCBOR(), rgbX);
        cnKeyPublic = new OneKey(key);

        key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        key.Add(KeyKeys.OKP_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.OKP_X.AsCBOR(), rgbX);
        cnKeyPublicCompressed = new OneKey(key);

        key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        key.Add(KeyKeys.OKP_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.OKP_D.AsCBOR(), rgbD);
        cnKeyPrivate = new OneKey(key);
    }

    public static void setUpClassForED448() throws CoseException {

        curve = KeyKeys.OKP_Ed448;
        signingAlgorithm = AlgorithmID.EDDSA.AsCBOR();

        Ed448KeyPairGenerator pGen = new Ed448KeyPairGenerator();
        Ed448KeyGenerationParameters genParam = new Ed448KeyGenerationParameters(null);
        pGen.init(genParam);

        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();

        Ed448PublicKeyParameters keyPublic = (Ed448PublicKeyParameters) p1.getPublic();
        Ed448PrivateKeyParameters keyPrivate = (Ed448PrivateKeyParameters) p1.getPrivate();

        byte[] rgbX = keyPublic.getEncoded();//keyPublic.normalize().getXCoord().getEncoded();
        //byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();
        //boolean signY = true;
        byte[] rgbD = keyPrivate.getEncoded();//keyPrivate.getD().toByteArray();

        CBORObject key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        key.Add(KeyKeys.OKP_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.OKP_X.AsCBOR(), rgbX);
        cnKeyPublic = new OneKey(key);

        key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        key.Add(KeyKeys.OKP_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.OKP_X.AsCBOR(), rgbX);
        cnKeyPublicCompressed = new OneKey(key);

        key = CBORObject.NewMap();
        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        key.Add(KeyKeys.OKP_Curve.AsCBOR(), curve);
        key.Add(KeyKeys.OKP_D.AsCBOR(), rgbD);
        cnKeyPrivate = new OneKey(key);
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        Sign1Message msg = new Sign1Message();
        msg.addAttribute(HeaderKeys.Algorithm, signingAlgorithm, Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.sign(cnKeyPrivate);
        byte[] rgbMsg = msg.EncodeToBytes();

        msg = (Sign1Message) Message.DecodeFromBytes(rgbMsg, MessageTag.Sign1);
        boolean f = msg.validate(cnKeyPublic);

        assert (f);
    }

    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTripMixed() throws Exception {
        System.out.println("Round Trip");
        Sign1Message msg = new Sign1Message();
        msg.addAttribute(HeaderKeys.Algorithm, signingAlgorithm, Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.sign(cnKeyPrivate);
        byte[] rgbMsg = msg.EncodeToBytes();

        msg = (Sign1Message) Message.DecodeFromBytes(rgbMsg, MessageTag.Sign1);
        boolean f = msg.validate(cnKeyPublic);

        assert (f);
    }

    @Test
    public void noAlgorithm() {
        CoseException thrown = assertThrows(
                CoseException.class,
                () -> {
                    Sign1Message msg = new Sign1Message();
                    msg.SetContent(rgbContent);
                    msg.sign(cnKeyPrivate);
                },
                "Ensure that the algorithm is provided");

        assertEquals("No Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void unknownAlgorithm() throws CoseException {
        Sign1Message msg = new Sign1Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.sign(cnKeyPrivate);
                });
        assertEquals("Unknown Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void unsupportedAlgorithm() {
        Sign1Message msg = new Sign1Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.sign(cnKeyPrivate);
                });
        assertEquals("Unsupported Algorithm Specified", thrown.getMessage());
    }

    @Test
    public void nullKey() throws CoseException {
        Sign1Message msg = new Sign1Message();
        OneKey key = null;

        assertThrows(NullPointerException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, signingAlgorithm, Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.sign(key);
                });
    }

    @Test
    public void noContent() throws CoseException {
        Sign1Message msg = new Sign1Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, signingAlgorithm, Attribute.PROTECTED);
                    msg.sign(cnKeyPrivate);
                });
        assertEquals("No Content Specified", thrown.getMessage());
    }

    @Test
    public void publicKey() throws CoseException {
        Sign1Message msg = new Sign1Message();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    msg.addAttribute(HeaderKeys.Algorithm, signingAlgorithm, Attribute.PROTECTED);
                    msg.SetContent(rgbContent);
                    msg.sign(cnKeyPublic);
                });
        assertEquals("Private key required to sign", thrown.getMessage());
    }

    @Test
    public void decodeWrongBasis() {
        CBORObject obj = CBORObject.NewMap();

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message.DecodeFromBytes(rgb, MessageTag.Sign1);
                });
        assertEquals("Message is not a COSE security Message", thrown.getMessage());
    }

    @Test
    public void codeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);


        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign1);
                });
        assertEquals("Invalid Sign1 structure", thrown.getMessage());
    }

    @Test
    public void decodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign1);
                });
        assertEquals("Invalid Sign1 structure", thrown.getMessage());
    }

    @Test
    public void decodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False.EncodeToBytes()));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign1);
                });
        assertEquals("Invalid Sign1 structure", thrown.getMessage());
    }

    @Test
    public void decodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign1);
                });
        assertEquals("Invalid Sign1 structure", thrown.getMessage());
    }

    @Test
    public void decodeBadContent() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign1);
                });
        assertEquals("Invalid Sign1 structure", thrown.getMessage());
    }

    @Test
    public void decodeBadSignature() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);

        CoseException thrown = assertThrows(CoseException.class,
                () -> {
                    byte[] rgb = obj.EncodeToBytes();
                    Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign1);
                });
        assertEquals("Invalid Sign1 structure", thrown.getMessage());
    }
}
