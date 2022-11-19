package levin.accountManagement.Login.registration;

import levin.accountManagement.Login.registration.PasswordReset.PasswordResetRequest;
import levin.accountManagement.Login.registration.PasswordReset.PasswordResetService;
import levin.accountManagement.Login.registration.PasswordReset.ResetPasswordRequest;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping(path = "/levin/api/")
@CrossOrigin("*")
@AllArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;
    private final LoginService loginService;
    private final PasswordResetService passwordResetService;


    @PostMapping(path = "registration")
    public String register(@RequestBody RegistrationRequest request)
    {
        return registrationService.register(request);
    }

    @PostMapping(path = "login")
    public Map<String, String> login(@RequestBody LoginRequest request)
    {
        return loginService.loginRequest(request);
    }

    @GetMapping(path = "confirm")
    public String confirm(@RequestParam("token") String token) {
        return registrationService.confirmToken(token);
    }

    //request the reset
    @PostMapping(path = "RequestReset")
    public String requestReset(@RequestBody PasswordResetRequest request)
    {
        return passwordResetService.requestReset(request);
    }

    //confirm reset in email
    @GetMapping("ConfirmPasswordReset")
    public String confirmPasswordReset(@RequestParam("token") String token) {
        return passwordResetService.confirmResetToken(token);
    }

    //update the password
    @PostMapping(path = "ResetPassword")
    public String resetPassword(@RequestBody ResetPasswordRequest request)
    {
        return passwordResetService.resetPassword(request);
    }




}
