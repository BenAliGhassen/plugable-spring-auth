package com.example.demo.User;
import java.util.List;
import java.util.UUID;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.example.demo.Security.AuthUser;
import com.example.demo.Security.AuthUserService;

//THE ADAPTER, THE BRIDGE IT BIND THE ENTITY CREATED BY THE TEMPLATE USERS TO THE USER DETAILS OBJ NEEDED IN OUR TOKENS LOGIC
@Service
public class AppUserDetailsService implements AuthUserService {
    private final UserRepository userRepo;

    public AppUserDetailsService(UserRepository userRepo){
        this.userRepo = userRepo;
    }

    //Create an AuthUser OBJ which is a UserDetails OBJ
    private AuthUser toAuthUser(User user){
        //Comment this line and use user.getRole() if your entity have a role attribute
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        return new AppAuthUser(user.getEmail(), user.getPassword(), authorities, user.getId().toString());
    }


    @Override
    public AuthUser loadUserByUsername(String userName){
        User user = userRepo.findByEmail(userName.trim().toLowerCase()).orElseThrow(() -> new UsernameNotFoundException("User Not Found"));

        return toAuthUser(user);
    }



    @Override 
    public AuthUser loadUserById(String userId){
        UUID id;
        try {
            id = UUID.fromString(userId);
        } catch (IllegalArgumentException e) {
            throw new UsernameNotFoundException("User Not Found");
        }
        User user = userRepo.findById(id).orElseThrow(() -> new UsernameNotFoundException("User Not Found"));
        return toAuthUser(user);
    }

}
