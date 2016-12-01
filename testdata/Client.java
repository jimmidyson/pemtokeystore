import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.io.*;

public class Client {
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      System.err.println("Usage: java Client <keystorePath> <url>");
      System.exit(1);
    }

    System.setProperty("javax.net.ssl.trustStore", args[0]);
    URL url = new URL(args[1]);
    HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
    BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
    String input;
    while ((input = br.readLine()) != null) {
      System.out.println(input);
    }
    br.close();
  }
}