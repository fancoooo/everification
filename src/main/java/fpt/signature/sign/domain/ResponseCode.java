package fpt.signature.sign.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "response_code", uniqueConstraints = {
        @UniqueConstraint(columnNames = "NAME", name = "UQ_RESPONSE_CODE_NAME")
})
@Cacheable
@Builder
@AllArgsConstructor
public class ResponseCode {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID", nullable = false, updatable = false)
    private Long id;

    @Column(name = "NAME", nullable = false, length = 64)
    private String name;

    @Column(name = "REMARK_EN", length = 256)
    private String remarkEn;

    @Column(name = "REMARK", length = 256)
    private String remark;

    public ResponseCode() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRemarkEn() {
        return remarkEn;
    }

    public void setRemarkEn(String remarkEn) {
        this.remarkEn = remarkEn;
    }

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }
}
