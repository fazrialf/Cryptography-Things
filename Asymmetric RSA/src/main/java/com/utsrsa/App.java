package com.utsrsa;

import java.security.Key;
import java.security.KeyPair;
import java.util.Scanner;
import org.apache.commons.codec.binary.Base64;

public class App 
{
    public static void main( String[] args )
    {
        Key kunciPublik = null;
        Key kunciPrivate = null;
        String isWantDemoAgain;

        System.out.println("Kriptografi Asimetris RSA on memory \n");
        RSAwithBC rsaBC = new RSAwithBC(2048);
        Scanner inputKeyboard = new Scanner(System.in);

        do{
            System.out.print("Ingin membuat pasangan kunci di memori (y/n) ? ");
            String isCreatePairKey = inputKeyboard.nextLine();
            if (isCreatePairKey.equalsIgnoreCase("y")){
                KeyPair pasanganKunci = rsaBC.generatePairKey();
                kunciPublik = pasanganKunci.getPublic();
                kunciPrivate = pasanganKunci.getPrivate();
                System.out.println("Kunci Publik : \n" + Base64.encodeBase64(kunciPublik.getEncoded()) + "\n");
                System.out.println("Kunci Private : \n" + Base64.encodeBase64(kunciPrivate.getEncoded()) + "\n");
            }

            System.out.print("Ingin melakukan enkripsi RSA (y/n) ? ");
            String isWantEncrypt = inputKeyboard.nextLine();

            if (isWantEncrypt.equalsIgnoreCase("y")){
                System.out.print("Masukkan plaintext : ");
                String plaintext = inputKeyboard.nextLine();
                String chipertext = rsaBC.encrypt(kunciPublik, plaintext);
                System.out.println("Chipertext : " + chipertext + "\n");
            }

            System.out.print("Ingin melakukan dekripsi RSA (y/n) ? ");
            String isWantDecrypt = inputKeyboard.nextLine();
            if (isWantDecrypt.equalsIgnoreCase("y")){
                System.out.print("Masukkan ciphertext : ");
                String ciphertext = inputKeyboard.nextLine();
                String decryptedText = rsaBC.decrypt(kunciPrivate, ciphertext);
                System.out.print("Hasil Dekripsi : " + decryptedText + "\n");
            }

            System.out.print("Ingin mengulang aplikasi kriptografi RSA lagi (y/n) ");
            isWantDemoAgain = inputKeyboard.nextLine();
        } while (isWantDemoAgain.equalsIgnoreCase("y"));
        inputKeyboard.close();
    }
}
