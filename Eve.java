import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;


public class Eve {

    private PublicKey publickeyAlice;
    private PublicKey publickeyBob;
    KeyAgreement keyAgreementAlice;
    KeyAgreement keyAgreementBob;
    byte[] sharedsecretAlice;
    byte[] sharedsecretBob;


    String ALGO = "RC2";

    Eve() {
        createParameters();
    }

    private void createParameters() {
        KeyPairGenerator kpgAlice = null;
        KeyPairGenerator kpgBob = null;
        try {
            kpgAlice = KeyPairGenerator.getInstance("DiffieHellman");
            kpgBob = KeyPairGenerator.getInstance("DiffieHellman");
            kpgAlice.initialize(1024);
            kpgBob.initialize(1024);
            KeyPair kpAlice = kpgAlice.generateKeyPair();
            KeyPair kpBob = kpgBob.generateKeyPair();
            publickeyAlice = kpAlice.getPublic();
            publickeyBob = kpBob.getPublic();
            keyAgreementAlice = KeyAgreement.getInstance("DiffieHellman");
            keyAgreementBob = KeyAgreement.getInstance("DiffieHellman");
            keyAgreementAlice.init(kpAlice.getPrivate());
            keyAgreementBob.init(kpBob.getPrivate());

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void publicKeyWithAlice(PublicKey publickey) {
        try {
            keyAgreementAlice.doPhase(publickey, true);
            sharedsecretAlice = keyAgreementAlice.generateSecret();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void publicKeyWithBob(PublicKey publickey) {
        try {
            keyAgreementBob.doPhase(publickey, true);
            sharedsecretBob = keyAgreementBob.generateSecret();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public String encryptAlice(String msg) {
        try {
            Key key = generateKeyAlice();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encodeByte = c.doFinal(msg.getBytes());
            return Base64.getEncoder().encodeToString(encodeByte);
        } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "error";
    }

    public String encryptBob(String msg) {
        try {
            Key key = generateKeyBob();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encodeByte = c.doFinal(msg.getBytes());
            return Base64.getEncoder().encodeToString(encodeByte);
        } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "error";
    }

    public String decryptAlice(String encryptedData) {
        try {
            Key key = generateKeyAlice();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decodeByte =  Base64.getDecoder().decode(encryptedData);
            byte[] decodeByteFinal = c.doFinal(decodeByte);
            return new String(decodeByteFinal);
        } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException  e) {
            e.printStackTrace();
        }
        return "error";
    }

    public String decryptBob(String encryptedData) {
        try {
            Key key = generateKeyBob();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decodeByte =  Base64.getDecoder().decode(encryptedData);
            byte[] decodeByteFinal = c.doFinal(decodeByte);
            return new String(decodeByteFinal);
        } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException  e) {
            e.printStackTrace();
        }
        return "error";
    }
    

    public PublicKey getPublickeyAlice() {
        return publickeyAlice;
    }

    public PublicKey getPublickeyBob() {
        return publickeyBob;
    }

    protected Key generateKeyAlice() {
        return new SecretKeySpec(sharedsecretAlice, ALGO);
    }

    protected Key generateKeyBob() {
        return new SecretKeySpec(sharedsecretBob, ALGO);
    }


    public String eveReceiveMessageFromAlice(String encryptedData, Bob bob) {

        String messageFromAliceDecrypted = decryptAlice(encryptedData);
        String messageToBobEncrypted = encryptBob(messageFromAliceDecrypted);
        String messageToBobDecrypted = bob.receiveMessageFromAlice(messageToBobEncrypted);
        return messageToBobDecrypted;

    }


    public String eveReceiveMessageFromBob(String encryptedData, Alice alice) {

        String messageFromBobDecrypted = decryptBob(encryptedData);
        String messageToAlliceEncrypted = encryptAlice(messageFromBobDecrypted);
        String messageToAlliceDecrypted = alice.receiveMessageFromBob(messageToAlliceEncrypted);
        return messageToAlliceDecrypted;


    }





    public void eavesdrop(Alice alice, Bob bob){
        publicKeyWithAlice(alice.getPublickey());
        alice.createPublicKey(getPublickeyAlice());
        publicKeyWithBob(bob.getPublickey());
        bob.createPublicKey(getPublickeyBob());
    }
}

