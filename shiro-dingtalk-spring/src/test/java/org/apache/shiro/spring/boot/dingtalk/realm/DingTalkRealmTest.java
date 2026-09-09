package org.apache.shiro.spring.boot.dingtalk.realm;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.spring.boot.dingtalk.token.DingTalkMaAuthenticationToken;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkScanCodeAuthenticationToken;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkTmpCodeAuthenticationToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import io.github.easy4j.dingtalk.service.DingTalkTemplate;

/**
 * Unit tests for DingTalk authorizing realm classes.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 */
@ExtendWith(MockitoExtension.class)
class DingTalkRealmTest {

    @Mock
    private DingTalkTemplate dingTalkTemplate;

    @Test
    @DisplayName("DingTalkMaAuthorizingRealm supports DingTalkMaAuthenticationToken")
    void maRealmSupportsCorrectToken() {
        DingTalkMaAuthorizingRealm realm = new DingTalkMaAuthorizingRealm(dingTalkTemplate);
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(DingTalkMaAuthenticationToken.class);
    }

    @Test
    @DisplayName("DingTalkScanCodeAuthorizingRealm supports DingTalkScanCodeAuthenticationToken")
    void scanCodeRealmSupportsCorrectToken() {
        DingTalkScanCodeAuthorizingRealm realm = new DingTalkScanCodeAuthorizingRealm(dingTalkTemplate);
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(DingTalkScanCodeAuthenticationToken.class);
    }

    @Test
    @DisplayName("DingTalkTempCodeAuthorizingRealm supports DingTalkTmpCodeAuthenticationToken")
    void tempCodeRealmSupportsCorrectToken() {
        DingTalkTempCodeAuthorizingRealm realm = new DingTalkTempCodeAuthorizingRealm(dingTalkTemplate);
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(DingTalkTmpCodeAuthenticationToken.class);
    }
}
