// package com.example.demo.RefreshToken;

// import static org.junit.jupiter.api.Assertions.assertEquals;
// import static org.junit.jupiter.api.Assertions.assertFalse;
// import static org.junit.jupiter.api.Assertions.assertThrows;
// import static org.junit.jupiter.api.Assertions.assertTrue;
// import static org.mockito.ArgumentMatchers.any;
// import static org.mockito.ArgumentMatchers.anyString;
// import static org.mockito.Mockito.mock;
// import static org.mockito.Mockito.never;
// import static org.mockito.Mockito.times;
// import static org.mockito.Mockito.verify;
// import static org.mockito.Mockito.when;

// import java.time.Instant;
// import java.util.List;
// import java.util.Optional;

// import org.junit.jupiter.api.Test;
// import org.mockito.ArgumentCaptor;

// import com.example.demo.User.User;

// class RefreshServiceTest {

//     private final RefreshRepository refreshRepo = mock(RefreshRepository.class);
//     private final RefreshService refreshService = new RefreshService(refreshRepo);

//     @Test
//     void rejectsExpiredRefreshToken() {
//         RefreshToken expiredToken = new RefreshToken(
//                 refreshService.hash("expired-token"),
//                 false,
//                 Instant.now().minusSeconds(1),
//                 new User("Test User", "test@example.com", "password"));
//         when(refreshRepo.findByValueForUpdate(anyString())).thenReturn(Optional.of(expiredToken));

//         assertThrows(InvalidToken.class, () -> refreshService.rotateRefreshToken("expired-token"));

//         verify(refreshRepo, never()).save(any(RefreshToken.class));
//     }

//     @Test
//     void rejectsRefreshTokenWithoutExpiry() {
//         RefreshToken tokenWithoutExpiry = new RefreshToken(
//                 refreshService.hash("legacy-token"),
//                 false,
//                 null,
//                 new User("Test User", "test@example.com", "password"));
//         when(refreshRepo.findByValueForUpdate(anyString())).thenReturn(Optional.of(tokenWithoutExpiry));

//         assertThrows(InvalidToken.class, () -> refreshService.rotateRefreshToken("legacy-token"));

//         verify(refreshRepo, never()).save(any(RefreshToken.class));
//     }

//     @Test
//     void generatedRefreshTokenHasSevenDayExpiry() {
//         User user = new User("Test User", "test@example.com", "password");
//         Instant beforeGeneration = Instant.now();

//         String rawToken = refreshService.generateRefreshToken(user);

//         Instant afterGeneration = Instant.now();
//         ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
//         verify(refreshRepo).save(tokenCaptor.capture());
//         Instant expiresAt = tokenCaptor.getValue().getExpiresAt();

//         assertFalse(expiresAt.isBefore(beforeGeneration.plus(RefreshService.REFRESH_TOKEN_TTL)));
//         assertFalse(expiresAt.isAfter(afterGeneration.plus(RefreshService.REFRESH_TOKEN_TTL)));
//         assertEquals(refreshService.hash(rawToken), tokenCaptor.getValue().getValue());
//     }

//     @Test
//     void rotationRevokesCurrentTokenAndGivesReplacementSevenDayExpiry() {
//         User user = new User("Test User", "test@example.com", "password");
//         RefreshToken currentToken = new RefreshToken(
//                 refreshService.hash("current-token"),
//                 false,
//                 Instant.now().plusSeconds(3600),
//                 user);
//         when(refreshRepo.findByValueForUpdate(anyString())).thenReturn(Optional.of(currentToken));
//         Instant beforeRotation = Instant.now();

//         RefreshTokenRotation rotation = refreshService.rotateRefreshToken("current-token");

//         Instant afterRotation = Instant.now();
//         ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
//         verify(refreshRepo, times(2)).save(tokenCaptor.capture());
//         List<RefreshToken> savedTokens = tokenCaptor.getAllValues();
//         RefreshToken replacementToken = savedTokens.get(1);

//         assertTrue(currentToken.isRevoked());
//         assertEquals(refreshService.hash(rotation.rawToken()), replacementToken.getValue());
//         assertFalse(replacementToken.getExpiresAt().isBefore(beforeRotation.plus(RefreshService.REFRESH_TOKEN_TTL)));
//         assertFalse(replacementToken.getExpiresAt().isAfter(afterRotation.plus(RefreshService.REFRESH_TOKEN_TTL)));
//     }
// }
