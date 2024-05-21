package fpt.signature.sign.ex;

import org.springframework.beans.factory.parsing.Problem;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)  // Nếu validate fail thì trả về 400
    public String handleBindException(BindException e) {
        // Trả về message của lỗi đầu tiên
        String errorMessage = "Request không hợp lệ";
        if (e.getBindingResult().hasErrors())
            e.getBindingResult().getAllErrors().get(0).getDefaultMessage();
        return errorMessage;
    }
    @ExceptionHandler({ NotFoundSignature.class })  // Có thể bắt nhiều loại exception
    public ResponseEntity<String> handleExceptionA(Exception e) {
        return ResponseEntity.status(404).body(e.getMessage());
    }

    // Có thêm các @ExceptionHandler khác...

    // Nên bắt cả Exception.class
    @ExceptionHandler({Exception.class})
    public ResponseEntity<Object> handleUnwantedException(BindException e) {
        // Log lỗi ra và ẩn đi message thực sự (xem phần 3.2)
        e.printStackTrace();  // Thực tế người ta dùng logger
        return ResponseEntity.status(500).body(e.toString());
    }
}
