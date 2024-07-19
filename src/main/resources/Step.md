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

Step => 19, Adding JWT Encoder and Getting started with JWT Resource.
1. When a user wants to talk to a rest API, he would need to create a JWT token by sending a basic authentication request 
with username and password.
2. Response will be a JWT token:
    
    Step 1 : Use BasicAuth for getting the JWT Token.
    Step2-n: Use JWT token as Bearer Token for authenticating request.


