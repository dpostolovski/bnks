package damjan.os;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

class SecondPhase{
    final byte[] ay;
    final byte[] ek;
    final byte[] params;

    public SecondPhase(byte[] ay, byte[] ek, byte[] params) {
        this.ay = ay;
        this.ek = ek;
        this.params = params;
    }
}

class Client
{
    Client partner = null;
    protected byte[] sharedKey = null;
    protected KeyPair keyPair;
    protected Cipher sharedKeyCipher;
    protected Signature rsa;
    protected byte[] axay = null;

    String name;

    PublicKey getPublicKey()
    {
        return this.keyPair.getPublic();
    }

    public Client(String name) throws Exception
    {
        this.name = name;
        KeyPairGenerator KpairGen = KeyPairGenerator.getInstance("RSA");
        KpairGen.initialize(2048);
        this.keyPair = KpairGen.generateKeyPair();

        sharedKeyCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        rsa = Signature.getInstance("SHA256withRSA");

    }

    void initiateProtocolWith(Client receiver) throws Exception
    {
        /*
         * Alice creates her own DH key pair with 2048-bit key size
         */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

        SecondPhase response = receiver.firstPhase(alicePubKeyEnc);


        /*
         * Alice uses Bob's public key for the first (and only) phase
         * of her version of the DH
         * protocol.
         * Before she can do so, she has to instantiate a DH public key
         * from Bob's encoded key material.
         */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        byte[] bobPubKeyEnc = response.ay;
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        System.out.println("ALICE: Execute PHASE1 ...");
        aliceKeyAgree.doPhase(bobPubKey, true);

        byte[] aliceSharedKey = aliceKeyAgree.generateSecret();

        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(response.params);


        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedKey, 0, 16, "AES");
        sharedKeyCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
        byte[] decrypted = sharedKeyCipher.doFinal(response.ek);

        rsa.initVerify(receiver.getPublicKey());
        rsa.update(joinAxAy(alicePubKeyEnc, bobPubKeyEnc));

        if(!rsa.verify(decrypted))
            throw new RuntimeException("Signature is not valid!");

        this.sharedKey = aliceSharedKey;
        partner = receiver;

        this.axay = joinAxAy(alicePubKeyEnc, bobPubKeyEnc);
        rsa.initSign(this.keyPair.getPrivate());
        rsa.update(axay);
        byte[] signed= rsa.sign();

        sharedKeyCipher.init(Cipher.ENCRYPT_MODE, aliceAesKey);
        byte[] signedAndEncrypted = sharedKeyCipher.doFinal(signed);
        byte[] encodedParams = sharedKeyCipher.getParameters().getEncoded();

        receiver.thirdPhase(signedAndEncrypted, this, encodedParams);
    }

    byte[] joinAxAy(byte[] ax, byte[] ay) throws Exception
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write( ax );
        outputStream.write( ay );
        return outputStream.toByteArray();
    }

    SecondPhase firstPhase(byte[] alicePubKeyEnc) throws Exception
    {
        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

        /*
         * Bob gets the DH parameters associated with Alice's public key.
         * He must use the same parameters when he generates his own key
         * pair.
         */
        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();

        // Bob creates his own DH key pair
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamFromAlicePubKey);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // Bob creates and initializes his DH KeyAgreement object
        System.out.println("BOB: Initialization ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob encodes his public key, and sends it over to Alice.
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

        bobKeyAgree.doPhase(alicePubKey, true);
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        this.sharedKey = bobSharedSecret;


        rsa.initSign(this.keyPair.getPrivate());

        this.axay = joinAxAy(alicePubKeyEnc, bobPubKeyEnc);
        rsa.update(axay);
        byte[] signed = rsa.sign();


        SecretKeySpec bobAesKey = new SecretKeySpec(this.sharedKey, 0, 16, "AES");
        sharedKeyCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);

        byte[] encryptedAndSigned = sharedKeyCipher.doFinal(signed);

        byte[] encodedParams = sharedKeyCipher.getParameters().getEncoded();

        return new SecondPhase(bobPubKeyEnc, encryptedAndSigned, encodedParams);
    }


    void thirdPhase(byte[] encryptedMessage, Client partner, byte[] encodedParams) throws Exception
    {
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);

        SecretKeySpec bobAesKey = new SecretKeySpec(this.sharedKey, 0, 16, "AES");
        sharedKeyCipher.init(Cipher.DECRYPT_MODE, bobAesKey,aesParams);
        byte[] decryptedMessage= sharedKeyCipher.doFinal(encryptedMessage);

        rsa.initVerify(partner.getPublicKey());
        rsa.update(axay);
        if(!rsa.verify(decryptedMessage))
            throw new RuntimeException("Signature is not valid!");

        this.partner = partner;
    }

    void sendMessage(byte[] cleartext) throws Exception
    {
        if(this.partner==null || this.sharedKey==null)
            throw new RuntimeException("Partner or key is not initialized.");

        SecretKeySpec bobAesKey = new SecretKeySpec(this.sharedKey, 0, 16, "AES");

        Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);

        byte[] ciphertext = bobCipher.doFinal(cleartext);

        // Retrieve the parameter that was used, and transfer it to Alice in
        // encoded format
        byte[] encodedParams = bobCipher.getParameters().getEncoded();
        partner.receiveMessage(ciphertext, encodedParams);
    }

    void receiveMessage(byte[] cipherText, byte[] encodedParams) throws Exception
    {
        if(this.partner==null || this.sharedKey==null)
            throw new RuntimeException("Partner or key is not initialized.");

        SecretKeySpec bobAesKey = new SecretKeySpec(this.sharedKey, 0, 16, "AES");

        // Instantiate AlgorithmParameters object from parameter encoding
        // obtained from Bob
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);
        Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, bobAesKey, aesParams);
        byte[] clearText = aliceCipher.doFinal(cipherText);

        System.out.println(name + " received message: ");
        System.out.println(new String(clearText));
    }


}

public class STS {

    public static void main(String[] args) throws Exception
    {
        Client alice = new Client("Alice");
        Client bob = new Client("Bob");

        alice.initiateProtocolWith(bob);
        alice.sendMessage("Test poraka od Alice!".getBytes("UTF-8"));
    }
}
