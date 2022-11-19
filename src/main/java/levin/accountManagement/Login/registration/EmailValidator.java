package levin.accountManagement.Login.registration;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;

@Service
public class EmailValidator implements Predicate<String> {

    //pres  ctrl + o to auto generate methods from parent class(in this case Predicate)
    @Override
    public boolean test(String s) {
        //TODO: regex to validate email
        return true;
    }
}
