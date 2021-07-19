import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;


public class Bob {

    private PublicKey publickey;
    KeyAgreement keyAgreement;
    byte[] sharedsecret;


    Bob() {
        createParameters();
    }

    private void createParameters() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("DiffieHellman");
            kpg.initialize(1024);
            KeyPair kp = kpg.generateKeyPair();
            publickey = kp.getPublic();
            keyAgreement = KeyAgreement.getInstance("DiffieHellman");
            keyAgreement.init(kp.getPrivate());

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void createPublicKey(PublicKey publickey) {
        try {
            keyAgreement.doPhase(publickey, true);
            sharedsecret = keyAgreement.generateSecret();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String msg) {
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance("RC2");
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encodeByte = c.doFinal(msg.getBytes());
            return Base64.getEncoder().encodeToString(encodeByte);
        } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "exception";
    }

    public String decrypt(String encryptedData) {
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance("RC2");
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decodeByte =  Base64.getDecoder().decode(encryptedData);
            byte[] decodeByteFinal = c.doFinal(decodeByte);
            return new String(decodeByteFinal);
        } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException  e) {
            e.printStackTrace();
        }
        return "exception";
    }

    public PublicKey getPublickey() {
        return publickey;
    }

    protected Key generateKey() {
        return new SecretKeySpec(sharedsecret, "RC2");
    }

    public String sendMessageToAlice(String msg, Alice alice, Eve eve, boolean isEveThere) {

        if(isEveThere) {
            String encodedMsg = encrypt(msg);
            String decodedMsg = eve.eveReceiveMessageFromBob(encodedMsg, alice);
            return decodedMsg;
        }
        String encodedMsg = encrypt(msg);
        String decodedMsg = alice.receiveMessageFromBob(encodedMsg);
        return decodedMsg;

    }



    public String receiveMessageFromAlice(String encryptedData) {

        String decodedMsg = decrypt(encryptedData);
        return decodedMsg;

    }

}

