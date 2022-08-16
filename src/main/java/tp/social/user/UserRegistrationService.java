package tp.social.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {

    private final UserFindService userFindService;
    private final UserRepository userRepository;

    public void requestRegistration(
            String name,
            String email
    ) {
        boolean exists = userFindService.existsByEmail(email);

        if (exists == false) {
            User user = new User(name, email);
            userRepository.save(user);
        }
    }
}
