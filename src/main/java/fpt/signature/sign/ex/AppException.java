package fpt.signature.sign.ex;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@AllArgsConstructor
@Data
public class AppException extends RuntimeException {
    private int code;
    private String message;

}
