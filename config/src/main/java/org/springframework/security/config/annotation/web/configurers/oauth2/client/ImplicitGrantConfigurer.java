/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;

import java.util.Base64;

/**
 * An {@link AbstractHttpConfigurer} for the OAuth 2.0 Implicit Grant type.
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following {@code Filter}'s are populated:
 *
 * <ul>
 * <li>{@link OAuth2AuthorizationRequestRedirectFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * The following shared objects are populated:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository} (required)</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 * <p>
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * </ul>
 *
 * @author Joe Grandja
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see ClientRegistrationRepository
 * @since 5.0
 */
public final class ImplicitGrantConfigurer<B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<ImplicitGrantConfigurer<B>, B> {

	private String authorizationRequestBaseUri;

	/**
	 * Sets the base {@code URI} used for authorization requests.
	 *
	 * @param authorizationRequestBaseUri
	 * 		the base {@code URI} used for authorization requests
	 *
	 * @return the {@link ImplicitGrantConfigurer} for further configuration
	 */
	public ImplicitGrantConfigurer<B> authorizationRequestBaseUri(String authorizationRequestBaseUri) {
		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		this.authorizationRequestBaseUri = authorizationRequestBaseUri;
		return this;
	}

	/**
	 * Sets the repository of client registrations.
	 *
	 * @param clientRegistrationRepository
	 * 		the repository of client registrations
	 *
	 * @return the {@link ImplicitGrantConfigurer} for further configuration
	 */
	public ImplicitGrantConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	@Override
	public void configure(B http) throws Exception {
		OAuth2AuthorizationRequestRedirectFilter authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
			this.getClientRegistrationRepository(), this.getAuthorizationRequestBaseUri(), getStringKeyGenerator(),
			getAuthorizationRequestRepository());
		http.addFilter(this.postProcess(authorizationRequestFilter));
	}

	private String getAuthorizationRequestBaseUri() {
		return this.authorizationRequestBaseUri != null ?
			this.authorizationRequestBaseUri :
			OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
	}

	private ClientRegistrationRepository getClientRegistrationRepository() {
		ClientRegistrationRepository clientRegistrationRepository = this.getBuilder().getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = this.getClientRegistrationRepositoryBean();
			this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private ClientRegistrationRepository getClientRegistrationRepositoryBean() {
		return this.getBuilder().getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
	}

	private StringKeyGenerator getStringKeyGenerator() {
		StringKeyGenerator stringKeyGenerator = this.getBuilder().getSharedObject(ApplicationContext.class).getBean(StringKeyGenerator.class);
		if (stringKeyGenerator == null) {
			stringKeyGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
			this.getBuilder().setSharedObject(StringKeyGenerator.class, stringKeyGenerator);
		}
		return stringKeyGenerator;
	}

	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> getAuthorizationRequestRepository() {
		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = this.getBuilder()
			.getSharedObject(ApplicationContext.class).getBean(AuthorizationRequestRepository.class);

		if (authorizationRequestRepository == null) {
			authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
			this.getBuilder().setSharedObject(AuthorizationRequestRepository.class, authorizationRequestRepository);
		}
		return authorizationRequestRepository;
	}
}
