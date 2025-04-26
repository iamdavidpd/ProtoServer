package Cifrado;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class CifradoUtils {
    
    private final static String PADDING = "AES/CBC/PKCS5Padding";

    public static byte[] simetricoCifrar(SecretKey llave, SecureRandom iv, String texto){
        byte[] textoCifrado;

        try {
            Cipher cifrador = Cipher.getInstance(PADDING);
            byte[] textoClaro = texto.getBytes();

            cifrador.init(Cipher.ENCRYPT_MODE, llave, iv);

            textoCifrado = cifrador.doFinal(textoClaro);

            return textoCifrado;
        } catch (Exception e){
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }

    public static byte[] simetricoDescifrar(SecretKey llave, SecureRandom iv, byte[] texto){
        byte[] textoClaro;

        try {
            Cipher	cifrador = Cipher.getInstance(PADDING);
            cifrador.init(Cipher.DECRYPT_MODE, llave, iv);
            textoClaro = cifrador.doFinal(texto);
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }

        return textoClaro;
    }
     
    public static byte[]  asimetricoCifrar(Key llave, String algoritmo, String texto){
        byte[] textoCifrado;

        try{
            Cipher cifrador = Cipher.getInstance(algoritmo);
            byte[] textoClaro = texto.getBytes();
        
            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);
            return textoCifrado;
        }catch (Exception e){
            System.out.println( "Excepcion: " + e.getMessage());
            return null;
        }
    }

    public static byte[] asimetricoDescifrar(Key llave, String algoritmo, byte[] texto){
        byte[] textoClaro;
        try{
            Cipher cifrador = Cipher.getInstance(algoritmo);
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro = cifrador.doFinal(texto);
        } catch (Exception e ){
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }

        return textoClaro;
    }
   
    public static PrivateKey leerPrivada(){
        PrivateKey privada;
        try {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ProtoServer/src/llaves/private.key"));
        privada = (PrivateKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e){
            e.printStackTrace();
            return null;
        }
        return privada;
    }

    public static PublicKey leerPublica(){
        PublicKey publica;
        try {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ProtoServer/src/llaves/public.key"));
        publica = (PublicKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e){
            e.printStackTrace();
            return null;
        }
        return publica;
    }

    public static byte[] getDigest(String algorithm, byte[] buffer){

        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(buffer);
            return digest.digest();

        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] hmac(String algoritmo, SecretKey llave, byte[] texto){
        byte[] digest = null;
        try {
            Mac mac = Mac.getInstance(algoritmo);
            mac.init(llave);
            digest = mac.doFinal(texto);
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
        }
        return digest;
    }

}
