package levin.accountManagement.Login.AppUser;

import levin.accountManagement.Login.registration.PasswordReset.PasswordResetTokenRepository;
import levin.accountManagement.Login.registration.token.ConfirmationToken;
import levin.accountManagement.Login.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class userService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "user with email %s not found";
    private final userRepository userRepo;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    private final PasswordResetTokenRepository forgotPasswordTokenRepository;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepo.findByEmail(email)
                .orElseThrow(
                        () -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email))
                );
    }

    public String signUpUser(AppUser appUser)
    {
        boolean userExists = userRepo.findByEmail(appUser.getEmail()).isPresent();

        if(userExists)
        {

            //TODO if email not confirmed, send confirmation email instead of throwing exception
            // Also check if user is the same
            throw new IllegalStateException("email already taken");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());

        appUser.setPassword(encodedPassword);

        userRepo.save(appUser);


        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(
                                                    token,
                                                    LocalDateTime.now(),
                                                    LocalDateTime.now().plusMinutes(15),
                                                    appUser
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);

        //TODO: Send Email
        return token;
    }

    public int enableAppUser(String email) {
        return userRepo.enableAppUser(email);
    }


}
