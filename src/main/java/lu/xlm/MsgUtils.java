package lu.xlm;

public class MsgUtils {

    public static void print(boolean isHeader, String message) {
        String m = "";
        if (isHeader) {
            m = "[+] ";
        }
        m += message;
        System.out.println(m);
    }
}
