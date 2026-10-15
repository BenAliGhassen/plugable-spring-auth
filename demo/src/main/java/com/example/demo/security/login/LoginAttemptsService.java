package com.example.demo.security.login;
import com.github.benmanes.caffeine.cache.Cache;
import org.springframework.stereotype.Service;
import com.example.demo.security.AuthProperties;
import com.github.benmanes.caffeine.cache.Caffeine;

@Service 
public class LoginAttemptsService {

    private final Cache<String, Integer> ips;
    private final Cache<String, Integer> pairs;
    private static final long MAX_ENTRIES = 100_000;

    private final AuthProperties authProps;
    public LoginAttemptsService(AuthProperties authProps){
        this.authProps = authProps;
        this.pairs = Caffeine.newBuilder().expireAfterWrite(authProps.login().window()).maximumSize(MAX_ENTRIES).build();
        this.ips = Caffeine.newBuilder().expireAfterWrite(authProps.login().window()).maximumSize(MAX_ENTRIES).build();
    }

    private String pairKey(String ip, String username){
        return ip + "|" + username.trim().toLowerCase();
    }

    private int count(Integer value){
        return value == null ? 0 : value;
    }

    public boolean isBlocked(String ip, String username){
        int pairsCount = count(pairs.getIfPresent(pairKey(ip, username)));
        int ipsCount = count(ips.getIfPresent(ip));
        if(pairsCount >= authProps.login().maxFailure() || ipsCount >= authProps.login().maxIpFailure()){
            return true;
        }
        return false;
    }

    public void recordFailure(String ip, String username){
        pairs.asMap().merge(pairKey(ip, username), 1, Integer::sum);
        ips.asMap().merge(ip, 1, Integer::sum);
    }

    public void recordSuccess(String ip, String username){
        pairs.invalidate(pairKey(ip, username));
    }
}
