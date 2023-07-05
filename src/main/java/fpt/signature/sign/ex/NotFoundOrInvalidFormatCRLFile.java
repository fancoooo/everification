package fpt.signature.sign.ex;

public class NotFoundOrInvalidFormatCRLFile extends Exception {
    public NotFoundOrInvalidFormatCRLFile() {
        super("Not found CRL File or Invalid format File CRL, check file CRL again");
    }
}
