package levin.accountManagement.Login.registration.PasswordReset;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
@ToString
public class ResetPasswordRequest {

    private final String token;
    private final String password;

}
