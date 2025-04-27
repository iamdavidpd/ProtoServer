package Servidores;

import java.net.Socket;

import Clientes.Cliente;

import java.io.IOException;

public class Main {

    public static void main(String[] args) {

        try {
            Socket socket = new Socket("localhost", 65000);
            Cliente cliente = new Cliente(socket);
            cliente.start();
            System.out.println("Cliente iniciado");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
