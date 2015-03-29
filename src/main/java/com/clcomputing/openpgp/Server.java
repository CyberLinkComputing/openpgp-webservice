package com.clcomputing.openpgp;

import com.sun.jersey.api.container.ContainerFactory;
import com.sun.jersey.api.container.grizzly2.GrizzlyServerFactory;
import com.sun.jersey.api.core.PackagesResourceConfig;
import com.sun.jersey.api.core.ResourceConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.ssl.SSLContextConfigurator;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;

import javax.ws.rs.core.UriBuilder;
import java.io.File;
import java.net.URI;
import java.security.Security;

public class Server {


    public static void main(String[] args) throws Exception {

        String httpIP = "0.0.0.0";
        int httpPort = 8080;

        String httpsIP = "0.0.0.0";
        int httpsPort = 8443;

        if (args.length>0)
        {
            int colonPosHttp =args[0].indexOf(':');

            if (-1 != colonPosHttp)
            {
                httpIP = args[0].substring(0,colonPosHttp);
                httpPort = Integer.parseInt(args[0].substring(colonPosHttp + 1));
            } else
            {
                httpPort = Integer.parseInt(args[0]);
            }

            if (args.length>1)
            {
                int colonPosHttps =args[1].indexOf(':');

                if (-1 != colonPosHttps)
                {
                    httpsIP = args[1].substring(0,colonPosHttps);
                    httpsPort = Integer.parseInt(args[1].substring(colonPosHttps + 1));
                } else
                {
                    httpsPort = Integer.parseInt(args[1]);
                }
            }
        }

        // Make the Bouncy Castle crypto library available
        Security.addProvider(new BouncyCastleProvider());

        // Start webserver for API
        ResourceConfig rc = new PackagesResourceConfig("com.clcomputing.openpgp.controllers");

        URI httpURI = UriBuilder.fromUri("http://" + httpIP)
                .port(httpPort)
                .build();

        URI httpsURI = UriBuilder.fromUri("https://" + httpsIP)
                .port(httpsPort)
                .build();

        // Non-SSL
        HttpServer http = GrizzlyServerFactory.createHttpServer(httpURI, rc);

        // SSL
        File sslP12 = new File("certs\\ssl.p12");
        if (sslP12.exists()) {
            SSLContextConfigurator sslCon = new SSLContextConfigurator();
            sslCon.setKeyStoreFile("certs\\ssl.p12"); // contains server keypair
            sslCon.setKeyStoreType("PKCS12");
            sslCon.setKeyStorePass("password");

            HttpServer secure = GrizzlyServerFactory.createHttpServer(httpsURI,
                    ContainerFactory.createContainer(HttpHandler.class, rc),
                    true,
                    new SSLEngineConfigurator(sslCon, false, false, false));
        } else {
            System.out.println("certs\\ssl.p12 file not found. HTTPS will not be enabled.");
        }

        System.out.println("Press enter to stop the server...");
        System.in.read();

    }
}
