package com.example.demo.security.refresh;
import java.time.Duration;
import java.time.Instant;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;


//THIS FILE CALL THE QUERY TO DELETE AN EXPIRED REFRESH TOKEN EVERYDAY AT 3AM
@Component 
public class RefreshTokenCleanup {
    private static final Logger log = Logger.getLogger(RefreshTokenCleanup.class.getName());
    private final RefreshRepository refreshRepo;
    // 0 secondes 0 minute 3 hours * any_day_of_month * any_month * any_day_of_week ===> everyday at 3am
    private final String cleanupCron = "${REFRESH_TOKEN_CLEANUP_CRON:0 0 3 * * *}";
    private final long retention;

    public RefreshTokenCleanup(RefreshRepository refreshRepo, @Value("${REFRESH_TOKEN_RETENTION_DAYS:3}") long retention) {
        this.refreshRepo = refreshRepo;
        this.retention = retention;
    }


    @Scheduled(cron = cleanupCron)
    @Transactional
    public void cleanupToken(){
        Instant cutoff = Instant.now().minus(Duration.ofDays(retention));
        int result = refreshRepo.deleteToken(cutoff);
        
        log.info("Refresh Token cleanup : " + result + " expired rows deleted");
    }
}
