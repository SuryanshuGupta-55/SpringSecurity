Step 10 => Creating Spring Security Configuration to Disable Csrf.

In this step we will setup our own security chain, 

	static class SecurityFilterChainConfiguration {

		@Bean
		@Order(SecurityProperties.BASIC_AUTH_ORDER)
		SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
			http.formLogin(withDefaults());
			http.httpBasic(withDefaults());
			return http.build();
		}
This is the default code which sets the SecurityFilterChain. We want to disable Csrf,
and form login and make stateless api therefore we will overwrite with our own in BasicAuthSecurityConfiguration.
