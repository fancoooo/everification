package fpt.signature.sign.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;


public class ResouceFile {
    @Value(value = "classpath:font/vuArial.ttf")
    private static Resource fontvuArial;

    public static String getFontPath() throws IOException {
        ClassPathResource classPathResource = new ClassPathResource("font/vuArial.ttf");
        return classPathResource.getPath();
    }
}
