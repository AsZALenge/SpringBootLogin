package com.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class OAuthConfiguration extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    private final UserDetailsService userService;

    @Value("${security.oauth2.client.client-id:clientId}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret:clientSecret}")
    private String clientSecret;

    @Value("${security.oauth2.client.access-token-validity-seconds:3600}") // 1 hours
    private int accessTokenValiditySeconds;

    @Value("${security.oauth2.client.authorized-grant-types: authorization_code, refresh_token, password, client_credentials}")
    private String[] authorizedGrantTypes;

    @Value("${security.oauth2.client.refresh-token-validity-seconds:86400}") // 1 days
    private int refreshTokenValiditySeconds;
    
    @Value("${security.oauth2.client.scope:read, write, trust}")
    private String[] scope;

    public OAuthConfiguration(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, UserDetailsService userService) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient(clientId)
                .secret(passwordEncoder.encode(clientSecret))
                .accessTokenValiditySeconds(accessTokenValiditySeconds)
                .refreshTokenValiditySeconds(refreshTokenValiditySeconds)
                .authorizedGrantTypes(authorizedGrantTypes)
                .scopes(scope)
                .resourceIds("resource_id");
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
               /** .accessTokenConverter(accessTokenConverter()) comment for not using jwt **/
                .userDetailsService(userService)
                .authenticationManager(authenticationManager);
    }

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security
	        .passwordEncoder(passwordEncoder)
	        .allowFormAuthenticationForClients()
	        .tokenKeyAccess("permitAll()")
	        .checkTokenAccess("isAuthenticated()");
	}

	/**
	comment for not using jwt
    @Bean
    JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        return converter;
    }
	**/
}
