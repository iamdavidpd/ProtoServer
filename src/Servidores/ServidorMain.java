package Servidores;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidKeySpecException;

import Cifrado.CifradoUtils;

import java.util.HashMap;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.KeyAgreement;

public class ServidorMain {
    private static HashMap<String, String> servicios = new HashMap<>();
    private static final int PUERTO = 65000;
    private static PublicKey llavePublicaFirmas;
    private static PrivateKey llavePrivadaFirmas;

    public static void main(String[] args){

        iniciarServicios();

        try {
            ServerSocket server = new ServerSocket(PUERTO);
            System.out.println("Servidor iniciado");

            //Paso 0a.
            llavePublicaFirmas = CifradoUtils.leerPublica();
            llavePrivadaFirmas = CifradoUtils.leerPrivada();

            Socket socket;
            DataInputStream in;
            ObjectOutputStream out;
            ObjectInputStream obIn;

            while (true) {
                socket = server.accept();
                in = new DataInputStream(socket.getInputStream());
                out = new ObjectOutputStream(socket.getOutputStream());

                //Recibimiento "hello"
                String saludo = in.readUTF();

                //Recibimiento reto
                int reto = in.readInt();
                byte[] retoBy = ByteBuffer.allocate(4).putInt(reto).array();

                //Creando rta y enviando
                Signature firma = Signature.getInstance("SHAwithRSA");
                firma.initSign(llavePrivadaFirmas);
                firma.update(retoBy);

                byte[] firmaBy = firma.sign();
                out.writeObject(firmaBy);

                //Recibiendo "OK"|"ERROR"
                String verRta = in.readUTF();
                if(verRta.equals("ERROR")){
                    System.out.println("ERROR");
                    continue;
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

                //Recibiendo "OK"|"ERROR"
                String verRta2 = in.readUTF();
                if(verRta2.equals("ERROR")){
                    System.out.println("ERROR");
                    continue;
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
                MessageDigest sha = MessageDigest.getInstance("SHA-512");
                byte[] k_ab1 = sha.digest(secretitoComp);

                byte[] aesKey = new byte[32];
                byte[] hmacKey = new byte[32];

                System.arraycopy(k_ab1, 0, aesKey, 0, 32);
                System.arraycopy(k_ab1, 32, hmacKey, 0, 32);

            }

        } catch (ClassNotFoundException | InvalidAlgorithmParameterException
            | IOException | NoSuchAlgorithmException | InvalidKeyException
            | SignatureException | InvalidParameterSpecException
            | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public static void iniciarServicios(){
        servicios.put("S1", "Estado vuelo");
        servicios.put("S2", "Disponibilidad vuelos");
        servicios.put("S3", "Costo de un vuelo");
    }

}
