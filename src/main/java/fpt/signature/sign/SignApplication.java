package fpt.signature.sign;

import fpt.signature.sign.general.Resources;
import org.apache.log4j.Logger;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;


@SpringBootApplication
@EnableConfigurationProperties
public class SignApplication {

    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.SignApplication.class);
    public static void main(String[] args) {

        SpringApplication.run(SignApplication.class, args);
        LOG.info("----------------------------------------------------------------");
        LOG.info("|                Welcome to everification service               |");
        LOG.info("|  (A component of Digital Trusted Identity Services - everify) |");
        LOG.info("|                     (Version 1.0.0)                           |");
        LOG.info("|            author: Ngo Gia Viet (vietng@fpt.com)              |");
        LOG.info("|                       FPT Information System                  |");
        LOG.info("|                                                               |");
        LOG.info("----------------------------------------------------------------");
    }
}
