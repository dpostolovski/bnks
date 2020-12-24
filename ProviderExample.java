import org.bouncycastle.crypto.ec.ECElGamalDecryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.MessageDigest;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Random;

class Frame{
    final byte[] sourceMAC;
    final byte[] destinationMAC;
    final byte[] data;


    public Frame(byte[] sourceMAC, byte[] destinationMAC, byte[] data) {
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
        this.data = data;
    }

    @Override
    public String toString()  {
        StringBuilder strb = new StringBuilder();
        strb.append("Source MAC: ");
        strb.append(Base64.getEncoder().encodeToString(sourceMAC));
        strb.append(System.lineSeparator());

        strb.append("Destination MAC: ");
        strb.append(Base64.getEncoder().encodeToString(destinationMAC));
        strb.append(System.lineSeparator());

        strb.append("Payload: ");
        strb.append(Base64.getEncoder().encodeToString(data));
        strb.append(System.lineSeparator());

        return strb.toString();
    }
}

class ClearTextFrame extends Frame {
    public ClearTextFrame(byte[] sourceMAC, byte[] destinationMAC, byte[] data) {
        super(sourceMAC, destinationMAC, data);
    }

    @Override
    public String toString(){
        StringBuilder strb = new StringBuilder();
        strb.append(super.toString());
        strb.append("Text: ");
        try {
            strb.append(new String(data, "UTF-8"));
            strb.append(System.lineSeparator());
        }catch (Exception e){  return super.toString();}

        return strb.toString();

    }
}

class EncryptedFrame extends Frame{
    final byte[] mic;

    public EncryptedFrame(byte[] sourceMAC, byte[] destinationMAC, byte[] data, byte[] mic) {
        super(sourceMAC,destinationMAC,data);
        this.mic = mic;
    }

    @Override
    public String toString() {
        StringBuilder strb = new StringBuilder();
        strb.append(super.toString());
        strb.append(System.lineSeparator());

        strb.append("MIC: ");
        strb.append(Base64.getEncoder().encodeToString(mic));
        strb.append(System.lineSeparator());

        return super.toString();
    }
}

public class ProviderExample {
    static byte [] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    Cipher cipherMIC = null;
    Cipher cipherEncryption = null;
    static ProviderExample instance;

    private ProviderExample() {
        try {
            cipherMIC = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherEncryption = Cipher.getInstance("AES/CTR/NoPadding");
        } catch (Exception e) {
            System.out.println("Nema shansi");
            return;
        }
    }

    static ProviderExample getInstance() {
        if (instance == null)
            instance = new ProviderExample();
        return instance;
    }

    static private byte[] xorBytes(byte[] array1, byte[] array2) {

        byte[] result = new byte[Math.min(array1.length, array2.length)];

        int i = 0;
        for (byte b : array1)
            result[i] = (byte) (b ^ array2[i++]);
        return result;
    }

    private static byte[] _calculateMIC(ClearTextFrame frame, byte[] key) throws Exception {
        ProviderExample.getInstance().cipherMIC.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(key), new IvParameterSpec(ProviderExample.iv));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(frame.sourceMAC);
        outputStream.write(frame.destinationMAC);
        outputStream.write(frame.data);

        byte[] mic = ProviderExample.getInstance().cipherMIC.doFinal(outputStream.toByteArray());

        return Arrays.copyOfRange(mic, 0, 8);

    }

    private static byte[] encryptDataFrame(byte[] data, byte[] key) throws Exception {
        ProviderExample.getInstance().cipherEncryption.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(key), new IvParameterSpec(ProviderExample.iv));

        return ProviderExample.getInstance().cipherEncryption.doFinal(data);
    }

    private static byte[] decryptDataFrame(byte[] data, byte[] key) throws Exception
    {
        ProviderExample.getInstance().cipherEncryption.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key), new IvParameterSpec(ProviderExample.iv));

        return ProviderExample.getInstance().cipherEncryption.doFinal(data);
    }

    public static SecretKeySpec getSecretKeySpec(byte[] keyBytes) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        keyBytes = sha.digest(keyBytes);
        keyBytes = Arrays.copyOf(keyBytes, 16);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        return secretKeySpec;
    }

    public static EncryptedFrame encryptedFrame(ClearTextFrame frame, String key) throws Exception {
        byte[] keyBytes = key.getBytes("UTF-8");
        ProviderExample.getInstance().cipherEncryption.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(keyBytes), new IvParameterSpec(ProviderExample.iv));

        byte[] encryptedData = ProviderExample.encryptDataFrame(frame.data, keyBytes);
        byte[] mic = ProviderExample._calculateMIC(frame, keyBytes);

        return new EncryptedFrame(
                frame.sourceMAC,
                frame.destinationMAC,
                encryptedData,
                mic);
    }

    static public ClearTextFrame decryptFrame(EncryptedFrame frame, String key) throws Exception {
        SecretKeySpec secretKeySpec = getSecretKeySpec(key.getBytes("UTF-8"));
        byte[] cipherText = frame.data;

        //Decrypt data
        byte[] plainText = ProviderExample.decryptDataFrame(frame.data, key.getBytes());

        //Verify integrity
        ClearTextFrame clearTextFrame = new ClearTextFrame(frame.sourceMAC, frame.destinationMAC, plainText);
        byte[] mic = ProviderExample._calculateMIC(clearTextFrame, key.getBytes("UTF-8"));

        if(!Arrays.areEqual(mic, frame.mic))
        {
            throw new IllegalStateException();
        }

        return new ClearTextFrame(frame.sourceMAC, frame.destinationMAC, plainText);
    }


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String key = "TestKluc";

        Random rd = new Random();
        byte[] sourceMac = new byte[8];
        byte[] destinationMac = new byte[8];
        rd.nextBytes(sourceMac);
        rd.nextBytes(destinationMac);

        ClearTextFrame clr = new ClearTextFrame(sourceMac, destinationMac, "test21231321ew4342432wqewopqeiwjqijwo".getBytes("UTF-8"));

        EncryptedFrame encryptedFrame = ProviderExample.encryptedFrame(clr, key);
        ClearTextFrame decryptedFrame = ProviderExample.decryptFrame(encryptedFrame, key);

        System.out.println(clr);
        System.out.println(encryptedFrame);
        System.out.println(decryptedFrame);

        assert Arrays.areEqual(clr.data, decryptedFrame.data);
        assert Arrays.areEqual(clr.sourceMAC, decryptedFrame.sourceMAC);
        assert Arrays.areEqual(clr.destinationMAC, decryptedFrame.destinationMAC);
        assert Arrays.areEqual(clr.data, decryptedFrame.data);
        assert Arrays.areEqual(clr.destinationMAC, encryptedFrame.destinationMAC);
        assert Arrays.areEqual(clr.sourceMAC, decryptedFrame.sourceMAC);

        assert !Arrays.areEqual(clr.data, encryptedFrame.data);


        rd.nextBytes(encryptedFrame.destinationMAC); // Tamper with destination mac;

        try{
            ProviderExample.decryptFrame(encryptedFrame, key);
            assert false;
        }catch (IllegalStateException e) { System.out.println("Integrity check failled"); }

        rd.nextBytes(encryptedFrame.data); // Tamper with data;

        try{
            ProviderExample.decryptFrame(encryptedFrame, key);
            assert false;
        }catch (IllegalStateException e) { System.out.println("Integrity check failled"); }

        rd.nextBytes(encryptedFrame.destinationMAC); // Tamper with source mac;

        try{
            ProviderExample.decryptFrame(encryptedFrame, key);
            assert false;
        }catch (IllegalStateException e) { System.out.println("Integrity check failled"); }


    }
}
