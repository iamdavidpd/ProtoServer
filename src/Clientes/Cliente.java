package Clientes;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.rmi.server.ObjID;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import Cifrado.CifradoUtils;

public class Cliente extends Thread{

    private PublicKey llavePublicaServidor ;
    private SecretKey llaveSesion;
    private SecretKey llaveHMAC;
    
    public PublicKey getLlavePublicaServidor() {
        return llavePublicaServidor;
    }
    public void setLlavePublicaServidor(PublicKey llavePublicaServidor) {
        this.llavePublicaServidor = llavePublicaServidor;
    }
    public SecretKey getLlaveSesion() {
        return llaveSesion;
    }
    public void setLlaveSesion(SecretKey llaveSesion) {
        this.llaveSesion = llaveSesion;
    }
    public SecretKey getLlaveHMAC() {
        return llaveHMAC;
    }
    public void setLlaveHMAC(SecretKey llaveHMAC) {
        this.llaveHMAC = llaveHMAC;
    }

    public void enviarSaludo(Socket socket) throws IOException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException, InvalidAlgorithmParameterException, InvalidKeySpecException{
        DataOutputStream s1 = new DataOutputStream(socket.getOutputStream());
        //hello
        s1.writeUTF("HELLO");
        s1.flush();
        //reto
        Random r = new Random();
        int reto = r.nextInt(10000);
        s1.writeInt(reto);
        //verificar firma y enviar ok o error 
        ObjectInputStream s2 = new ObjectInputStream(socket.getInputStream()); 
        int longitudllavePublicaRSA = s2.readInt();
        byte[] claveBytes = new byte[longitudllavePublicaRSA];
        s2.readFully(claveBytes);

        PublicKey clavePublica = CifradoUtils.leerPublica();

        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(reto);
        byte[] rta =buffer.array();

        Signature sig = Signature.getInstance(("SHA256withRSA"));
        sig.initVerify(clavePublica);
        sig.update(rta);

        if (sig.verify(claveBytes)){
            DataOutputStream s3 = new DataOutputStream(socket.getOutputStream());
            s1.writeUTF("OK");
        }
        else{
            DataOutputStream s4 = new DataOutputStream(socket.getOutputStream());
            s1.writeUTF("ERROR");
        }
        socket.close();
        //verificar DH
        ObjectInputStream s5 = new ObjectInputStream(socket.getInputStream());
        int longitudClave = s5.readInt();
        byte[] claveB = new byte[longitudClave];
        s2.readFully(claveB);

        PublicKey claveP = CifradoUtils.leerPublica();

        BigInteger G = (BigInteger) s5.readObject();
        BigInteger P = (BigInteger) s5.readObject();
        BigInteger Gx = (BigInteger) s5.readObject();

        int longitudFirma = s5.readInt();
        byte[] firmaB = new byte[longitudFirma];
        s5.readFully(firmaB);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(G);
        oos.writeObject(P);
        oos.writeObject(Gx);
        oos.flush();

        byte[] datosFirmados = baos.toByteArray();

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(clavePublica);
        sign.update(datosFirmados);

        DataOutputStream s6 = new DataOutputStream(socket.getOutputStream());
        if (sig.verify(firmaB)) {
                s6.writeUTF("OK");
        } else {
            s6.writeUTF("ERROR");
        }

        //calcular gxy
        DHParameterSpec dhParams = new DHParameterSpec(P, G);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhParams);
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        DHPublicKeySpec keySpec = new DHPublicKeySpec(Gx, P, G);
        PublicKey clavePublicaCliente = keyFactory.generatePublic(keySpec);

        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(clavePublicaCliente, true);
        byte[] sharedSecret = keyAgree.generateSecret();

        //llave simetrica para cifrar K_AB1 Y MAC K_AB2
        MessageDigest sha  = MessageDigest.getInstance("SHA-512");
        byte[] k_ab1 = sha.digest(sharedSecret);

        byte[] aesKey = new byte[32];
        byte[] hmacKey = new byte[32];
        System.arraycopy(k_ab1, 0, aesKey, 0, 32);
        System.arraycopy(k_ab1, 32, hmacKey, 0, 32);
        //obtener el y  generar el IV y enviarlo al servidor
        BigInteger gy = ((DHPublicKey) publicKey).getY();

        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);

        ObjectOutputStream salida = new ObjectOutputStream(socket.getOutputStream());
        salida.writeObject(gy);
        salida.writeObject(ivBytes);

        // verificacion hmac
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        int longC = dis.readInt();
        byte[] encrypt = dis.readNBytes(longC);

        int longM = dis.readInt();
        byte[] rmac = dis.readNBytes(longM);

        Mac hmac = Mac.getInstance("HmacSHA-512");
       
    }

    


    }





