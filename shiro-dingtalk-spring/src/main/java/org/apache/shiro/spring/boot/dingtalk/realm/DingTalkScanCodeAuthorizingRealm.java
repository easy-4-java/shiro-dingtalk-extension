package org.apache.shiro.spring.boot.dingtalk.realm;

import java.util.Objects;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.spring.boot.dingtalk.authc.DingTalkScanCodeLoginRequest;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkScanCodeAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse.UserInfo;
import io.github.easy4j.dingtalk.service.DingTalkTemplate;
import com.taobao.api.ApiException;

/**
 * Shiro authorizing realm for DingTalk scan-code (QR code) authentication.
 *
 * <p>Validates the application key, calls the DingTalk SNS API to retrieve user
 * info by the temporary login code, populates the token with unionid/openid/userInfo,
 * and delegates to the authentication repository. Notifies registered realm listeners
 * on success or failure.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class DingTalkScanCodeAuthorizingRealm extends AbstractAuthorizingRealm {

	private static final Logger LOG = LoggerFactory.getLogger(DingTalkScanCodeAuthorizingRealm.class);

	private final DingTalkTemplate dingTalkTemplate;

	public DingTalkScanCodeAuthorizingRealm(DingTalkTemplate dingTalkTemplate) {
		this.dingTalkTemplate = dingTalkTemplate;
	}

	@Override
	public Class<? extends AuthenticationToken> getAuthenticationTokenClass() {
		return DingTalkScanCodeAuthenticationToken.class;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		LOG.info("Handle authentication token {}.", token);
		AuthenticationException ex = null;
		AuthenticationInfo info = null;
		try {
			DingTalkScanCodeAuthenticationToken dingTalkToken = (DingTalkScanCodeAuthenticationToken) token;
			DingTalkScanCodeLoginRequest loginRequest = (DingTalkScanCodeLoginRequest) dingTalkToken.getPrincipal();
			validateAppKey(loginRequest.getKey());
			if (!StringUtils.hasText(loginRequest.getLoginTmpCode())) {
				throw new DingTalkCodeNotFoundException("No loginTmpCode found in request.");
			}
			String corpId = dingTalkTemplate.getCorpId(loginRequest.getKey());
			String appSecret = dingTalkTemplate.getAppSecret(corpId, loginRequest.getKey());
			OapiSnsGetuserinfoBycodeResponse response = dingTalkTemplate.opsForSns()
					.getUserinfoByTmpCode(loginRequest.getLoginTmpCode(), loginRequest.getKey(), appSecret);
			if (!response.isSuccess()) {
				LOG.error(response.getBody());
				throw new DingTalkAuthenticationServiceException(response.getErrmsg());
			}
			UserInfo userInfo = response.getUserInfo();
			dingTalkToken.setUnionid(userInfo.getUnionid());
			dingTalkToken.setOpenid(userInfo.getOpenid());
			dingTalkToken.setUserInfo(userInfo);
			info = getRepository().getAuthenticationInfo(dingTalkToken);
		} catch (AuthenticationException e) {
			ex = e;
		} catch (io.github.easy4j.dingtalk.error.DingTalkApiException e) {
			ex = new AuthenticationException(e);
		} catch (ApiException e) {
			ex = new AuthenticationException(e);
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
