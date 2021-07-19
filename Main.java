import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.io.*;



public class Main {

    public static void main(String[] args)  {
        boolean isEveThere = true;

        Alice alice = new Alice();
        Bob bob = new Bob();
        Eve eve = new Eve();
        if(isEveThere){
            eve.eavesdrop(alice, bob);

            String test1 = alice.sendMessageToBob("HiBob", bob, eve, isEveThere);
            System.out.println("message from Bob was: HiBob"  +"message from Alice decrypted-Eve as:" +test1);
            String test2 = bob.sendMessageToAlice("HiAllice", alice, eve, isEveThere);
            System.out.println("message from Bob was: HiAllice"  +"message from Bob decrypted-Eve as:" +test2);
        } else {
            alice.createPublicKey(bob.getPublickey());
            bob.createPublicKey(alice.getPublickey());
            String test1 = alice.sendMessageToBob("HiBob", bob, eve, isEveThere);
            System.out.println("message from Bob was: HiBob"  +"message from Alice decrypted as:" +test1);
            String test2 = bob.sendMessageToAlice("HiAllice", alice, eve, isEveThere);
            System.out.println("message from Bob was: HiAllice"  +"message from Bob decrypted as:" +test2);
        }
    }
}