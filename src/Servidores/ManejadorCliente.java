package Servidores;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Cifrado.CifradoUtils;

public class ManejadorCliente extends Thread {
    private Socket socket;
    private static PrivateKey llavePrivadaFirmas;
    private int contador;


    public ManejadorCliente(Socket socket, int contador) {
        this.socket = socket;
        llavePrivadaFirmas = CifradoUtils.leerPrivada();
        this.contador = contador;
        }

    public void run(){
        DataInputStream in;
        ObjectOutputStream out;
        ObjectInputStream obIn;

        try {
            in = new DataInputStream(socket.getInputStream());
            out = new ObjectOutputStream(socket.getOutputStream());

            //Recibimiento "hello"
            in.readUTF();

            //Recibimiento reto
            int reto = in.readInt();
            byte[] retoBy = ByteBuffer.allocate(4).putInt(reto).array();

            //Creando rta y enviando
            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initSign(llavePrivadaFirmas);
            firma.update(retoBy);

            byte[] firmaBy = firma.sign();
            out.writeObject(firmaBy);

            //Recibiendo "OK"|"ERROR"
            String verRta = in.readUTF();
            if(verRta.equals("ERROR")){
                System.out.println("ERROR");
                throw new Exception("Error en la firma del reto");
            } else {
                System.out.println("(Usuario " + contador + ")" + " Respuesta verificacion RTA: OK");
            }

            //Paso 7. Generacion de G, P y G^x
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();

            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);
            BigInteger P = dhSpec.getP();
            BigInteger G = dhSpec.getG();

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(dhSpec);
            KeyPair keyPa = keyPairGen.genKeyPair();

            PublicKey publicaDiffie = keyPa.getPublic();
            PrivateKey privadaDiffie = keyPa.getPrivate();

            BigInteger Gx = ((DHPublicKey) publicaDiffie).getY();

            //Generacion de F(K_w-, (G, P, G^x))
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);

            oos.writeObject(G);
            oos.writeObject(P);
            oos.writeObject(Gx);
            oos.flush();

            byte[] mensaje = baos.toByteArray();

            Signature firma2 = Signature.getInstance("SHA256withRSA");
            firma2.initSign(llavePrivadaFirmas);
            firma2.update(mensaje);

            byte[] firma2By = firma2.sign();

            //Envio G, P, G^x & F(K_w-, (G, P, G^x))
            out.writeObject(G);
            out.writeObject(P);
            out.writeObject(Gx);
            out.writeObject(firma2By);
            out.flush();

            //Recibiendo "OK"|"ERROR"
            String verRta2 = in.readUTF();
            if(verRta2.equals("ERROR")){
                System.out.println("ERROR");
                throw new Exception("Error en la firma del mensaje G, P, G^x & F(K_w-, (G, P, G^x))");
            } else {
                System.out.println("(Usuario " + contador + ")" +" Respuesta verificacion F(K_w-, (G, P, G^x)): OK");
            }

            //Recibimiento G^y
            obIn = new ObjectInputStream(socket.getInputStream());
            BigInteger Gy = (BigInteger) obIn.readObject();

            //Calculo G^yx
            DHPublicKeySpec clienteGy = new DHPublicKeySpec(Gy, P, G);
            KeyFactory keyFac = KeyFactory.getInstance("DH");
            PublicKey llaveGy = keyFac.generatePublic(clienteGy);
            KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
            keyAgree.init(privadaDiffie);
            keyAgree.doPhase(llaveGy, true);
            byte[] secretitoComp = keyAgree.generateSecret();

            //Generar llave para cifrar K_AB1
            byte[] k_ab1 = CifradoUtils.getDigest("SHA-512", secretitoComp);

            byte[] aesKey = new byte[32];
            byte[] hmacKey = new byte[32];

            System.arraycopy(k_ab1, 0, aesKey, 0, 32);
            System.arraycopy(k_ab1, 32, hmacKey, 0, 32);
            SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
            SecretKeySpec hmacKeySpec = new SecretKeySpec(hmacKey, "HmacSHA256");

            //Recibiendo vector de inicializacion
            byte[] iv = new byte[16];
            iv = (byte[]) obIn.readObject();
            IvParameterSpec ivSec = new IvParameterSpec(iv);

            //Cifrado hash
            HashMap<String, String> servicios = ServidorMain.getServicios();
            DataOutputStream out2 = new DataOutputStream(socket.getOutputStream());
            int tamanoHash = servicios.size();
            out2.writeInt(tamanoHash);
            String servCompleto = "";
            for(String clave : servicios.keySet()){
                String servicio = clave + " " + servicios.get(clave);
                servCompleto += servicio;
                byte[] cif = CifradoUtils.simetricoCifrar(aesKeySpec, ivSec, servicio);
                out.writeObject(cif);
                out.flush();
            }
            byte[] servcomby = servCompleto.getBytes();
            byte[] hmc = CifradoUtils.hmac("HMACSHA256", hmacKeySpec, servcomby);
            out.writeObject(hmc);
            out.flush();

            byte[] cifradoServer = (byte[]) obIn.readObject();
            byte[] hmacServer = (byte[]) obIn.readObject();

            byte[] desciServer = CifradoUtils.simetricoDescifrar(aesKeySpec, ivSec, cifradoServer);
            byte[] hmacServerDesc = CifradoUtils.hmac("HMACSHA256", hmacKeySpec, desciServer);

            if(Arrays.equals(hmacServerDesc, hmacServer)){
                InetAddress inet = InetAddress.getLocalHost();
                String ip = inet.getHostAddress();
                String completo = ip + ":" +"65000";
                byte[] completoBy = completo.getBytes();
                byte[] cifradoCompleto = CifradoUtils.simetricoCifrar(aesKeySpec, ivSec, completo);
                byte[] hmacCompleto = CifradoUtils.hmac("HMACSHA256", hmacKeySpec, completoBy);
                out.writeObject(cifradoCompleto);
                out.writeObject(hmacCompleto);
                out.flush();

            //Recibiendo "OK"|"ERROR"
            String verIP = in.readUTF();
            if(verIP.equals("ERROR")){
                System.out.println("ERROR");
                throw new Exception("Error en el hmac del mensaje IP:PUERTO");
                } else {
                System.out.println("(Usuario " + contador + ")" + " Respuesta verificacion IP:PUERTO: OK");
                }
            } else {
                throw new Exception("HMAC incorrecto");
            }

        } catch (Exception e) {
        e.printStackTrace();
        }
    }
}
