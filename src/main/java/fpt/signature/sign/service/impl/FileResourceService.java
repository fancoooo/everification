package fpt.signature.sign.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Scanner;

@Service
public class FileResourceService {
    private final ResourceLoader resourceLoader;
    private final Logger log = LoggerFactory.getLogger(FileResourceService.class);
    public FileResourceService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public String readFileToString(String filePath) throws IOException {
        Resource resource = resourceLoader.getResource("classpath:" + filePath);
        try (Scanner scanner = new Scanner(resource.getInputStream())) {
            StringBuilder stringBuilder = new StringBuilder();
            while (scanner.hasNextLine()) {
                stringBuilder.append(scanner.nextLine()).append("\n");
            }
            return stringBuilder.toString();
        } catch (IOException e) {
            e.printStackTrace();
            log.error("read file in resource error:" + e.getMessage());
            return null;
        }
    }
}
