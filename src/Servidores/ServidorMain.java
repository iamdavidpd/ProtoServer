package Servidores;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

public class ServidorMain {
    private static HashMap<String, String> servicios = new HashMap<>();
    private static final int PUERTO = 65000;

    public static void main(String[] args){

        iniciarServicios();

        try {
            ServerSocket server = new ServerSocket(PUERTO);
            System.out.println("Servidor iniciado");
            Socket socket;

            while (true) {
                socket = server.accept();
                new Thread(new ManejadorCliente(socket)).start();

                System.out.println("Cliente conectado: " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort());
                System.out.println("Esperando cliente...");

            }

        } catch (IOException e) {
            System.out.println("Error al iniciar el servidor: " + e.getMessage());
        }
    }

    public static void iniciarServicios(){
        servicios.put("S1", "Estado vuelo");
        servicios.put("S2", "Disponibilidad vuelos");
        servicios.put("S3", "Costo de un vuelo");
    }

    public static HashMap<String, String> getServicios() {
        return servicios;
    }

}
