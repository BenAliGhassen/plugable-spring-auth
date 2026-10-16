package com.example.demo.security;
import static org.assertj.core.api.Assertions.assertThat;


import org.junit.jupiter.api.Test;

import com.example.demo.security.LogSanitizer;

public class LogSanitizerTest {
    @Test
    void replacesLineFeedWithUnderscore() {
        String input = "x\nFAKE LINE";

        String result = LogSanitizer.cleanString(input);

        assertThat(result).isEqualTo("x_FAKE LINE");
    }

    @Test
    void replacesCarriageReturnWithUnderscore() {
        String result = LogSanitizer.cleanString("a\rb");
        assertThat(result).isEqualTo("a_b");
    }

    @Test
    void returnsTheTextNullForNullInput() {
        assertThat(LogSanitizer.cleanString(null)).isEqualTo("null");
    }

    @Test
    void leavesNormalTextUnchanged() {
        assertThat(LogSanitizer.cleanString("ali@example.com")).isEqualTo("ali@example.com");
    }

    @Test
    void replacesWindowsLineEndingWithTwoUndersscores() {
        assertThat(LogSanitizer.cleanString("x\r\nFAKE")).isEqualTo("x__FAKE");
    }
}
