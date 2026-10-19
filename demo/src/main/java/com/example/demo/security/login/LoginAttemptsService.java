package com.example.demo.security.login;
import com.github.benmanes.caffeine.cache.Cache;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.demo.security.AuthProperties;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;

@Service 
public class LoginAttemptsService {

    private final Cache<String, Integer> ips;
    private final Cache<String, Integer> pairs;
    private static final long MAX_ENTRIES = 100_000;
    private final AuthProperties authProps;

    //Same as refreshService, this cloack was previously invesible but called by caffeine we make visible so we can tests it
    @Autowired 
    public LoginAttemptsService(AuthProperties authProps){
        this(authProps, Ticker.systemTicker());
    }

    LoginAttemptsService(AuthProperties authProps, Ticker ticker){
        this.authProps = authProps;
        this.pairs = Caffeine.newBuilder().expireAfterWrite(authProps.login().window()).maximumSize(MAX_ENTRIES).ticker(ticker).build();
        this.ips = Caffeine.newBuilder().expireAfterWrite(authProps.login().window()).maximumSize(MAX_ENTRIES).ticker(ticker).build();
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
