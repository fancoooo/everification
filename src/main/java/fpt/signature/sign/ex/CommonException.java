package fpt.signature.sign.ex;

import org.springframework.http.HttpStatus;

import java.util.Objects;

public class CommonException extends RuntimeException {

    private final HttpStatus httpStatus;

    private final String code;

    private final String message;

    public CommonException(ErrorCodeEnum errorCode) {
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
        this.httpStatus = HttpStatus.OK;
    }

    public CommonException(ErrorCodeEnum errorCode, String message) {
        this.code = errorCode.getCode();
        this.message = message;
        this.httpStatus = HttpStatus.OK;
    }

    public CommonException(HttpStatus httpStatus, ErrorCodeEnum errorCode) {
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
        this.httpStatus = httpStatus;
    }

    public CommonException(HttpStatus httpStatus, String message) {
        this.code = httpStatus.value() + "";
        this.message = message;
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CommonException that = (CommonException) o;
        return httpStatus == that.httpStatus && Objects.equals(code, that.code) && Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(httpStatus, code, message);
    }
}
