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

Step => 13

Will store the user details in H2 database from in-memory database.
when we set up the H2 page will give error because of frames.
By default, spring security disable frames.
=> 
`http.headers().framesOptions().sameOrigin()`

The above code is deprecated use:

`http.headers(headers -> headers.frameOptions(frameOptionsConfig-> frameOptionsConfig.disable()));`

There is a class as JdbcDaoImpl, there is a file as well users.ddl which creates the Data Structure.
So, we will use this to setup our database, for user details.
