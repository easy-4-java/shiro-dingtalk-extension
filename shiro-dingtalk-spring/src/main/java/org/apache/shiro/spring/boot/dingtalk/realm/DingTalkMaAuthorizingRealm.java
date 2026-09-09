package org.apache.shiro.spring.boot.dingtalk.realm;

import java.util.Objects;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkMaLoginRequest;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkMaAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import io.github.easy4j.dingtalk.service.DingTalkTemplate;
import com.taobao.api.ApiException;

/**
 * Shiro authorizing realm for DingTalk Mini-Application (MA) authentication.
 *
 * <p>Validates the application key, exchanges the authorization code for an access
 * token via {@link DingTalkTemplate}, and delegates to the authentication repository
 * to build the {@link AuthenticationInfo}. Notifies registered realm listeners on
 * success or failure.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class DingTalkMaAuthorizingRealm extends AbstractAuthorizingRealm {

	private static final Logger LOG = LoggerFactory.getLogger(DingTalkMaAuthorizingRealm.class);

	private final DingTalkTemplate dingTalkTemplate;

	public DingTalkMaAuthorizingRealm(DingTalkTemplate dingTalkTemplate) {
		this.dingTalkTemplate = dingTalkTemplate;
	}

	@Override
	public Class<? extends AuthenticationToken> getAuthenticationTokenClass() {
		return DingTalkMaAuthenticationToken.class;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		LOG.info("Handle authentication token {}.", token);
		AuthenticationException ex = null;
		AuthenticationInfo info = null;
		try {
			DingTalkMaAuthenticationToken dingTalkToken = (DingTalkMaAuthenticationToken) token;
			DingTalkMaLoginRequest loginRequest = (DingTalkMaLoginRequest) dingTalkToken.getPrincipal();
			validateAppKey(loginRequest.getKey());
			if (!StringUtils.hasText(loginRequest.getAuthCode())) {
				throw new DingTalkCodeNotFoundException("No authCode found in request.");
			}
			String corpId = dingTalkTemplate.getCorpId(loginRequest.getKey());
			loginRequest.setAccessToken(dingTalkTemplate.getAccessToken(corpId, loginRequest.getKey()));
			info = getRepository().getAuthenticationInfo(dingTalkToken);
		} catch (AuthenticationException e) {
			ex = e;
		} catch (ApiException e) {
			ex = new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
		}
		notifyListeners(token, ex, info);
		if (Objects.nonNull(ex)) {
			throw ex;
		}
		return info;
	}

	private void validateAppKey(String key) {
		if (!StringUtils.hasText(key) || !dingTalkTemplate.hasAppKey(key)) {
			throw new DingTalkCodeNotFoundException("Invalid App Key.");
		}
	}

	private void notifyListeners(AuthenticationToken token, AuthenticationException ex, AuthenticationInfo info) {
		if (Objects.nonNull(getRealmsListeners()) && !getRealmsListeners().isEmpty()) {
			for (AuthorizingRealmListener realmListener : getRealmsListeners()) {
				if (Objects.nonNull(ex) || Objects.isNull(info)) {
					realmListener.onFailure(this, token, ex);
				} else {
					realmListener.onSuccess(this, info);
				}
			}
		}
	}

}
