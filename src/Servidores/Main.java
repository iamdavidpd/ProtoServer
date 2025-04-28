package Servidores;

import java.net.Socket;

import Clientes.Cliente;

import java.io.IOException;

public class Main {

    public static void main(String[] args) {
        String host = "localhost";
        int port = 65000;

        try {

            Thread ejecutarServer = new Thread(() -> ServidorMain.main(new String[0]));
            ejecutarServer.start();

            for(int i = 0; i < 2; i++){
                Socket socket = new Socket(host, port);
                Cliente cliente = new Cliente(socket);
                cliente.start();
                System.out.println("Cliente #" + (i+1) + " conectado" );
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
