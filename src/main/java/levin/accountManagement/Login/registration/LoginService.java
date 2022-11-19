package levin.accountManagement.Login.registration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import levin.accountManagement.Login.AppUser.AppUser;
import levin.accountManagement.Login.AppUser.userRepository;
import levin.accountManagement.Login.AppUser.userRole;
import levin.accountManagement.Login.AppUser.userService;
import levin.accountManagement.Login.email.EmailSender;
import levin.accountManagement.Login.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Service
@AllArgsConstructor
public class LoginService {
    private final userService userServiceObj;
    private EmailValidator emailValidator;
    private final userRepository userRepo;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    public Map<String, String> loginRequest(LoginRequest request) {
        boolean isValidEmail = userRepo.findByEmail(request.getEmail()).isPresent();
        Map<String, String> response = new HashMap<>();
        if(isValidEmail)
        {
            AppUser user = (AppUser) userServiceObj.loadUserByUsername(request.getEmail());

            if(user.getEmail().equals(request.getEmail())
                    && bCryptPasswordEncoder.matches(request.getPassword(), user.getPassword()))
            {
                //secret string woudlnt be used in production and would be something secret and secured, imported externally
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                List<String> roles = Collections.singletonList(String.valueOf(user.getRole()));

                String access_token = JWT.create()
                        .withSubject(user.getEmail())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10*60*1000*6))
                        .withIssuer("Levin Authentication Server - T")
                        .withClaim("roles", roles)
                        .sign(algorithm);

                String refresh_token = JWT.create()
                        .withSubject(user.getEmail())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10*60*1000*6*10))
                        .withIssuer("Levin Authentication Server - T")
                        .sign(algorithm);

                response.put("Login_Response", "Login Successful");
                response.put("access_token", access_token);
                response.put("refresh_token", refresh_token);

                return response;
            }
            else {
               /* return "USER INFO: " + user.getEmail() + " " + user.getPassword()
                        + "\n REQUEST INFO: " + request.getEmail() + " " + request.getPassword();*/
                throw new IllegalStateException("email/pass not valid");
            }
        }
        else
        {
            throw new IllegalStateException("email/pass not valid");
        }
    }

    public String authenticateAccessToken(String token) {
        try{
            Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(token);
            String username = decodedJWT.getSubject();

            //for role authentication purposes
//            String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
//            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//            stream(roles).forEach(role -> {
//                authorities.add(new SimpleGrantedAuthority(role));
//            });

           if(userRepo.findByEmail(username).isPresent())
           {
               return "Token Authenticated";
           }
           else {
               return "Invalid Token";
           }

        }catch(Exception exception){
            return "Failed to Authenticate";
        }
    }
}
