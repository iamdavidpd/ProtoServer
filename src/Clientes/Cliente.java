package Clientes;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Cifrado.CifradoUtils;

public class Cliente extends Thread{

    private PublicKey llavePublicaServidor ;
    private SecretKey llaveSesion;
    private SecretKey llaveHMAC;
    private Socket socket;

    public Cliente(Socket socket) {
        this.socket = socket;
    }
    
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

    @Override
    public void run() {
        try {
            enviarSaludo(socket);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void enviarSaludo(Socket socket) throws IOException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException, InvalidAlgorithmParameterException, InvalidKeySpecException{
        DataOutputStream sdo1 = new DataOutputStream(socket.getOutputStream());
        //hello
        sdo1.writeUTF("HELLO");
        sdo1.flush();
        //reto
        Random r = new Random();
        int reto = r.nextInt(10000);
        sdo1.writeInt(reto);sdo1.flush();
        //verificar firma y enviar ok o error 
        ObjectInputStream soi2 = new ObjectInputStream(socket.getInputStream()); 
        int longitudllavePublicaRSA = soi2.readInt();
        byte[] sigReto = new byte[longitudllavePublicaRSA];
        soi2.readFully(sigReto);

        PublicKey clavePublica = CifradoUtils.leerPublica();

        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(reto);
        byte[] rta =buffer.array();

        Signature sig = Signature.getInstance(("SHA256withRSA"));
        sig.initVerify(clavePublica);
        sig.update(rta);

        if (sig.verify(sigReto)){
            sdo1.writeUTF("OK");
            sdo1.flush();
        }
        else{
            sdo1.writeUTF("ERROR");
            sdo1.flush();
        }
      
        //verificar DH
        int longitudClave = soi2.readInt();
        byte[] claveB = new byte[longitudClave];
        soi2.readFully(claveB);

        PublicKey claveP = CifradoUtils.leerPublica();

        BigInteger G = (BigInteger) soi2.readObject();
        BigInteger P = (BigInteger) soi2.readObject();
        BigInteger Gx = (BigInteger) soi2.readObject();

        int longitudFirma = soi2.readInt();
        byte[] firmaB = new byte[longitudFirma];
        soi2.readFully(firmaB);

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

        if (sig.verify(firmaB)) {
                sdo1.writeUTF("OK");sdo1.flush();
        } else {
            sdo1.writeUTF("ERROR");sdo1.flush();
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

        byte[] aesBytes = new byte[32];
        byte[] hmacBytes = new byte[32];
        System.arraycopy(k_ab1, 0, aesBytes, 0, 32);
        System.arraycopy(k_ab1, 32, hmacBytes, 0, 32);
        
        SecretKeySpec aesKeySpec  = new SecretKeySpec(aesBytes, "AES");
        SecretKeySpec hmacKeySpec = new SecretKeySpec(hmacBytes, "HmacSHA256");
        //obtener el y  generar el IV y enviarlo al servidor
        BigInteger gy = ((DHPublicKey) publicKey).getY();

        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);

        ObjectOutputStream salida = new ObjectOutputStream(socket.getOutputStream());
        salida.writeObject(gy);
        salida.writeObject(ivBytes);
        salida.flush();

        // verificacion hmac
        SecureRandom ivSec = new SecureRandom(ivBytes);

        Mac hmac = Mac.getInstance("HmacSHA256");

        // --- Paso 13 & 13b: recibir servicios + HMAC y verificar HMAC ---
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        int count = dis.readInt();
        List<String> servicios = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            byte[] encSvc = (byte[]) soi2.readObject();
            byte[] decSvc = CifradoUtils.simetricoDescifrar(aesKeySpec, ivSec, encSvc);
            servicios.add(new String(decSvc, StandardCharsets.UTF_8));
        }
        byte[] macServicios = (byte[]) soi2.readObject();
        hmac.init(hmacKeySpec);
        byte[] calcSvcMac = hmac.doFinal(String.join("", servicios).getBytes(StandardCharsets.UTF_8));
        if (!Arrays.equals(calcSvcMac, macServicios)) {
            throw new SecurityException("HMAC servicios inválido");
        }
         // 14) Enviar id_servicio+IP cliente cifrados + HMAC
         String idSvc = servicios.get(0).split(" ")[0];
         String ipCli = InetAddress.getLocalHost().getHostAddress();
         String payload14 = idSvc + ipCli;
         byte[] enc14 = CifradoUtils.simetricoCifrar(aesKeySpec, ivSec, payload14);
         byte[] mac14 = hmac.doFinal(payload14.getBytes(StandardCharsets.UTF_8));
         oos.writeObject(enc14);
         oos.writeObject(mac14);
         oos.flush();
 
         // 16) Recibir ip_servidor+puerto cifrados + HMAC
         byte[] enc16 = (byte[]) soi2.readObject();
         byte[] mac16 = (byte[]) soi2.readObject();
         hmac.init(hmacKeySpec);
         byte[] dec16 = CifradoUtils.simetricoDescifrar(aesKeySpec, ivSec, enc16);
         byte[] calc16 = hmac.doFinal(dec16);
 
         // 17 & 18) Confirmar al servidor
         sdo1.writeUTF(Arrays.equals(calc16, mac16) ? "OK" : "ERROR");
         sdo1.flush();
 
         socket.close();
    }

    


    }





