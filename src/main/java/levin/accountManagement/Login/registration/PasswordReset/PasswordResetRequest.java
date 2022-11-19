package levin.accountManagement.Login.registration.PasswordReset;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

@Getter
@EqualsAndHashCode
@ToString
public class PasswordResetRequest {

    private final String email;


    @JsonCreator
    public PasswordResetRequest(@JsonProperty("email") String email){
        this.email = email;
    }

}
