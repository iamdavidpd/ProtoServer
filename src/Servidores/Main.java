package Servidores;

import java.net.Socket;
import java.util.Scanner;

import Clientes.Cliente;

import java.io.IOException;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Seleccione el escenario:");
        System.out.println("1. Cliente iterativo (32 consultas secuenciales)");
        System.out.println("2. Clientes concurrentes (4, 16, 32, 64 clientes)");

        int escenario = scanner.nextInt();
        scanner.nextLine(); // limpiar salto de línea

        String host = "localhost"; // o la IP del servidor
        int port = 65000; // cambia el puerto si es necesario

        switch (escenario) {
            case 1:
                correrEscenario1(host, port);
                break;
            case 2:
                correrEscenario2(host, port);
                break;
            default:
                System.out.println("Escenario no válido.");
                break;
        }
        scanner.close();
    }

    private static void correrEscenario1(String host, int port) {
        try {
            for (int i = 0; i < 32; i++) {
                Socket socket = new Socket(host, port);
                Cliente cliente = new Cliente(socket);
                cliente.enviarSaludo(socket);
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void correrEscenario2(String host, int port) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Ingrese el número de clientes concurrentes (4, 16, 32, 64):");
        int numClientes = scanner.nextInt();
        scanner.nextLine(); // limpiar salto de línea

        Cliente[] clientes = new Cliente[numClientes];

        try {
            for (int i = 0; i < numClientes; i++) {
                Socket socket = new Socket(host, port);
                clientes[i] = new Cliente(socket);
                clientes[i].start();
            }

            // Esperar a que todos los clientes terminen
            for (int i = 0; i < numClientes; i++) {
                clientes[i].join();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
