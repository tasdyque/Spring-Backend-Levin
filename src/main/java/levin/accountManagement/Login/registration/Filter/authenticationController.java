package levin.accountManagement.Login.registration.Filter;

import levin.accountManagement.Login.registration.LoginService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/levin/authenticate/")
@CrossOrigin("*")
@AllArgsConstructor
public class authenticationController {

    private final LoginService loginService;

    @GetMapping(path = "authenticateAccessToken")
    public String authenticateAccessToken(@RequestParam("token") String token)
    {
        return loginService.authenticateAccessToken(token);
    }

}
