package fpt.signature.sign.ex;

public enum ErrorCodeEnum {
    USERNAME_DUPLICATE("1001", "Username already exists in the database"),
    OWNER_NOT_FOUND("1002", "Owner not exists in the database"),
    AGREEMENT_ASSIGNED("1005", "Agreement already assigned by ownerId"),
    RELYING_PARTY_NOT_FOUND("1003", "Relying party not exists in the database"),
    RELYING_PARTY_DUPLICATE("1004", "Relying party already exists in the database");

    private final String code;

    private final String message;

    ErrorCodeEnum(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
