package com.clcomputing.datapower.openpgp;

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

        // Make the Bouncy Castle crypto library available
        Security.addProvider(new BouncyCastleProvider());

        // Start webserver for API
        ResourceConfig rc = new PackagesResourceConfig("com.clcomputing.datapower.openpgp.controllers");

        URI httpURI = UriBuilder.fromUri("http://0.0.0.0")
                .port(8080)
                .build();

        URI httpsURI = UriBuilder.fromUri("https://0.0.0.0")
                .port(8443)
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
