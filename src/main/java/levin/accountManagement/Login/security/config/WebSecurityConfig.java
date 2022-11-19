package levin.accountManagement.Login.security.config;


import levin.accountManagement.Login.AppUser.userService;
import levin.accountManagement.Login.registration.Filter.jwtFilter;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;

@Configuration
@AllArgsConstructor
@EnableWebSecurity
@CrossOrigin("*")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final userService userServiceObj;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    private jwtFilter jwtFilterObj;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(bCryptPasswordEncoder);
        provider.setUserDetailsService(userServiceObj);
        return provider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {



        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/levin/api/**")
                .permitAll()
                .anyRequest().authenticated();


        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(jwtFilterObj, UsernamePasswordAuthenticationFilter.class);



//        http.addFilter(null);

        /*http
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll();*/



    }
}
