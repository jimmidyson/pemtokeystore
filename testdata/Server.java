import javax.net.ssl.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.Key;
import java.security.cert.Certificate;

public class Server {
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      System.err.println("Usage: java Server <keystorePath> <port>");
      System.exit(1);
    }

    // load certificate
    char[] storepass = "changeit".toCharArray();
    char[] keypass = "changeit".toCharArray();
    String alias = "server";
    FileInputStream fIn = new FileInputStream(args[0]);
    KeyStore keystore = KeyStore.getInstance("JKS");
    keystore.load(fIn, storepass);
    // display certificate
    Certificate cert = keystore.getCertificate(alias);
    System.out.println(cert);
    Key key = keystore.getKey(alias, keypass);
    System.out.println(key);
    // setup the key manager factory
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keystore, keypass);
    // setup the trust manager factory
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    tmf.init(keystore);

    // create https server
    final HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", Integer.parseInt(args[1])), 0);
    // create ssl context
    SSLContext sslContext = SSLContext.getInstance("TLS");
    // setup the HTTPS context and parameters
    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
      public void configure(HttpsParameters params) {
        try {
          // initialise the SSL context
          SSLContext c = SSLContext.getDefault();
          SSLEngine engine = c.createSSLEngine();
          params.setNeedClientAuth(false);
          params.setCipherSuites(engine.getEnabledCipherSuites());
          params.setProtocols(engine.getEnabledProtocols());
          // get the default parameters
          SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
          params.setSSLParameters(defaultSSLParameters);
        } catch (Exception e) {
          e.printStackTrace();
          System.out.println("Failed to create HTTPS server");
        }
      }
    });
    server.start();
  }
}
