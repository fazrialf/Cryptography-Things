package com.utsrsa;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.*;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class RSAwithBC {
    int keySize;

    public RSAwithBC(){
        this.keySize = 1024;
    }

    public RSAwithBC(int keySize){
        this.keySize = keySize;
    }

    public KeyPair generatePairKey(){
        try{
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            SecureRandom random = createFixedRandom();
            generator.initialize(keySize, random);

            KeyPair keypair = generator.generateKeyPair();
            Key pubKey = keypair.getPublic();
            Key privKey = keypair.getPrivate();

            return keypair;
        } catch (Exception e){
            System.out.println(e.toString());
        }
        return null;
    }

    public String encrypt(Key keyPublic, String inputData){
        String encryptedData = null;
        try{
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)PublicKeyFactory.createKey((keyPublic.getEncoded()));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            byte[] messageBytes = inputData.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

            encryptedData = getHexString(hexEncodedCipher);
        } catch(Exception e){
            System.out.println(e);
        }
        return encryptedData;
    }

    public String decrypt(Key keyPrivate, String encryptedData){
        String outputData = null;
        try{
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            AsymmetricKeyParameter privateKey = (AsymmetricKeyParameter)PrivateKeyFactory.createKey(keyPrivate.getEncoded());
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);

            byte[] messageBytes = hexStringToByteArray(encryptedData);
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
            outputData = new String(hexEncodedCipher);
        } catch (Exception e){
            System.out.println(e.toString());
        }
        return outputData;
    }

    private SecureRandom createFixedRandom(){
        return new FixedRand();
    }

    private class FixedRand extends SecureRandom{
        private static final long serialVersionUID = 1L;
        MessageDigest sha;
        byte[] state;

        FixedRand(){
            try{
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();
            } catch (NoSuchAlgorithmException e){
                throw new RuntimeException("gagal mendapatkan SHA-1!");
            }
        }

        public void nextBytes(byte[] bytes){
            int off = 0;
            sha.update(state);
            while (off < bytes.length) {
                state = sha.digest();
                if (bytes.length - off > state.length){
                    System.arraycopy(state, 0, bytes, off, state.length);
                } else {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }
                off += state.length;
                sha.update(state);
            }
        }
    }

    public static String getHexString(byte[] b) throws Exception{
        String result = "";
        for (int i = 0; i < b.length; i++){
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    public static byte[] hexStringToByteArray(String s){
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2){
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String readFileAsString(String filePath) throws java.io.IOException{
        StringBuffer fileData = new StringBuffer(1000);
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead = 0;
        while ((numRead = reader.read(buf)) != -1){
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
            buf = new char[1024];
        }
        reader.close();
        return fileData.toString();
    }
}
