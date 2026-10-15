package com.example.demo.security.refresh;
import java.time.Instant;
import java.util.logging.Logger;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.security.AuthProperties;


//THIS FILE CALL THE QUERY TO DELETE AN EXPIRED REFRESH TOKEN EVERYDAY AT 3AM
@Component 
public class RefreshTokenCleanup {
    private static final Logger log = Logger.getLogger(RefreshTokenCleanup.class.getName());
    private final RefreshRepository refreshRepo;
    private final AuthProperties authProps;
    // 0 secondes 0 minute 3 hours * any_day_of_month * any_month * any_day_of_week ===> everyday at 3am
    private final String cleanupCron = "${REFRESH_TOKEN_CLEANUP_CRON:0 0 3 * * *}";
    

    public RefreshTokenCleanup(RefreshRepository refreshRepo, AuthProperties authProps) {
        this.refreshRepo = refreshRepo;
        this.authProps = authProps;
    }


    @Scheduled(cron = cleanupCron)
    @Transactional
    public void cleanupToken(){
        Instant cutoff = Instant.now().minus(authProps.refresh().retention());
        int result = refreshRepo.deleteToken(cutoff);
        
        log.info("Refresh Token cleanup : " + result + " expired rows deleted");
    }
}
