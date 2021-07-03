package com.utssimetrikripto;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SymetricCrypto {
    private String algorithm; // dapat menggunakan bentuk "AES/ECB/PKCS5Padding"
    private SecretKeySpec secretKey;
    private byte[] key;

    public SymetricCrypto() throws NoSuchPaddingException, NoSuchAlgorithmException{
        this.algorithm = "AES";
    }

    public SymetricCrypto(String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException{
        this.algorithm = algorithm;
    }

    private void setKey(String myKey){
        MessageDigest sha = null;
        try{
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, algorithm);
        } catch (UnsupportedEncodingException e){
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public String encrypt(String plaintext, String password){
        try{
            setKey(password);
            Cipher cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
            return Base64.encodeBase64String(ciphertext);
        } catch (Exception e){
            System.out.println("Error while encrypting: " + e.toString());;
        }
        return null;
    }

    public String decrypt(String ciphertext, String password){
        try{
            setKey(password);
            Cipher cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] ciphertextDecode = Base64.decodeBase64(ciphertext.getBytes());
            byte[] plaintext = cipher.doFinal(ciphertextDecode);
            return new String(plaintext, "UTF-8");
        } catch (Exception e){
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}
