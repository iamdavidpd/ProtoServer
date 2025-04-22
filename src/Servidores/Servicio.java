package Servidores;

public class Servicio {
    private String id;
    private String nombre;
    private String ip;
    private int puerto;

    public Servicio(String id, String nombre, String ip, int puerto) {
        this.id = id;
        this.nombre = nombre;
        this.ip = ip;
        this.puerto = puerto;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public int getPuerto() {
        return puerto;
    }

    public void setPuerto(int puerto) {
        this.puerto = puerto;
    }

}
