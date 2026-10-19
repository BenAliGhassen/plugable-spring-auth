package com.example.demo.security.refresh;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.example.demo.security.AuthProperties;


//THIS FILE CALL THE QUERY TO DELETE AN EXPIRED REFRESH TOKEN ON AUTH_CLEANUP_CRON ->(EVERYDAY AT 3AM by default)
@Component 
public class RefreshTokenCleanup {
    private static final Logger log = LoggerFactory.getLogger(RefreshTokenCleanup.class);
    private final RefreshRepository refreshRepo;
    private final AuthProperties authProps;
    private final Clock clock;
    // 0 secondes 0 minute 3 hours * any_day_of_month * any_month * any_day_of_week ===> everyday at 3am
    private static  final String cleanupCron = "${AUTH_CLEANUP_CRON:0 0 3 * * *}";
    
    @Autowired 
    public RefreshTokenCleanup(RefreshRepository refreshRepo, AuthProperties authProps) {
        this(refreshRepo, authProps, Clock.systemUTC());
    }

    RefreshTokenCleanup(RefreshRepository refreshRepo, AuthProperties authProps, Clock clock) {
        this.refreshRepo = refreshRepo;
        this.authProps = authProps;
        this.clock = clock;
    }


    @Scheduled(cron = cleanupCron)
    @Transactional
    public void cleanupToken(){
        Instant cutoff = Instant.now(clock).minus(authProps.refresh().retention());
        int result = refreshRepo.deleteToken(cutoff);
        
        log.info("Refresh Token cleanup expired rows rows={} deleted",result);
    }
}
