<?php

/**
 * @mainpage
 * OAuth 2.0 server in PHP, originally written for
 * <a href="http://www.opendining.net/"> Open Dining</a>. Supports
 * <a href="http://tools.ietf.org/html/draft-ietf-oauth-v2-10">IETF draft v10</a>.
 *
 * - By Tim Ridgely <tim.ridgely@gmail.com>.
 * - Updated to draft v10 by Aaron Parecki <aaron@parecki.com>.
 *
 * @see http://code.google.com/p/oauth2-php/
 */

ini_set('display_errors', 1);
error_reporting(E_ALL | E_STRICT);

/**
 * @defgroup oauth2_credentials Client Credentials
 * @{
 *
 * When interacting with the authorization server, the client identifies
 * itself using a client identifier and authenticates using a set of
 * client credentials. This specification provides one mechanism for
 * authenticating the client using password credentials.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-2
 */

/**
 * Regex to filter out the client identifier (described in Section 2 of IETF draft).
 *
 * IETF draft does not prescribe a format for these, however I've arbitrarily
 * chosen alphanumeric strings with hyphens and underscores, 3-32 characters
 * long.
 *
 * Feel free to change.
 */
define("OAUTH2_CLIENT_ID_REGEXP", "/^[a-z0-9-_]{3,32}$/i");

/**
 * @}
 */


/**
 * @defgroup oauth2_authorization Obtaining End-User Authorization
 * @{
 *
 * When the client interacts with an end-user, the end-user MUST first
 * grant the client authorization to access its protected resources.
 * Once obtained, the end-user access grant is expressed as an
 * authorization code which the client uses to obtain an access token.
 * To obtain an end-user authorization, the client sends the end-user to
 * the end-user authorization endpoint.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3
 */

/**
 * Denotes "token" authorization response type.
 */
define("OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN", "token");

/**
 * Denotes "code" authorization response type.
 */
define("OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE", "code");

/**
 * Denotes "code-and-token" authorization response type.
 */
define("OAUTH2_AUTH_RESPONSE_TYPE_CODE_AND_TOKEN", "code-and-token");

/**
 * Regex to filter out the authorization response type.
 */
define("OAUTH2_AUTH_RESPONSE_TYPE_REGEXP", "/^(token|code|code-and-token)$/");

/**
 * @}
 */


/**
 * @defgroup oauth2_access_token Obtaining an Access Token
 * @{
 *
 * The client obtains an access token by authenticating with the
 * authorization server and presenting its access grant (in the form of
 * an authorization code, resource owner credentials, an assertion, or a
 * refresh token).
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4
 */

/**
 * Denotes "authorization_code" grant types (for token obtaining).
 */
define("OAUTH2_GRANT_TYPE_AUTH_CODE", "authorization_code");

/**
 * Denotes "password" grant types (for token obtaining).
 */
define("OAUTH2_GRANT_TYPE_USER_CREDENTIALS", "password");

/**
 * Denotes "assertion" grant types (for token obtaining).
 */
define("OAUTH2_GRANT_TYPE_ASSERTION", "assertion");

/**
 * Denotes "refresh_token" grant types (for token obtaining).
 */
define("OAUTH2_GRANT_TYPE_REFRESH_TOKEN", "refresh_token");

/**
 * Denotes "none" grant types (for token obtaining).
 */
define("OAUTH2_GRANT_TYPE_NONE", "none");

/**
 * Regex to filter out the grant type.
 */
define("OAUTH2_GRANT_TYPE_REGEXP", "/^(authorization_code|password|assertion|refresh_token|none)$/");

/**
 * @}
 */


/**
 * @defgroup oauth2_protected Accessing a Protected Resource
 * @{
 *
 * Clients access protected resources by presenting an access token to
 * the resource server. Access tokens act as bearer tokens, where the
 * token string acts as a shared symmetric secret. This requires
 * treating the access token with the same care as other secrets (e.g.
 * end-user passwords). Access tokens SHOULD NOT be sent in the clear
 * over an insecure channel.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5
 */

/**
 * Used to define the name of the OAuth access token parameter (POST/GET/etc.).
 *
 * IETF Draft sections 5.1.2 and 5.1.3 specify that it should be called
 * "oauth_token" but other implementations use things like "access_token".
 *
 * I won't be heartbroken if you change it, but it might be better to adhere
 * to the spec.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.1.2
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.1.3
 */
define("OAUTH2_TOKEN_PARAM_NAME", "oauth_token");

/**
 * @}
 */


/**
 * @defgroup oauth2_error Error handling
 * @{
 *
 * @todo Extend for i18n.
 */

/**
 * "Bad Request" HTTP status code.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.2.1
 */
define("OAUTH2_ERROR_HTTP_BAD_REQUEST", "400 Bad Request");

/**
 * "Unauthorized" HTTP status code.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.2.1
 */
define("OAUTH2_ERROR_HTTP_UNAUTHORIZED", "401 Unauthorized");

/**
 * "Forbidden" HTTP status code.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.2.1
 */
define("OAUTH2_ERROR_HTTP_FORBIDDEN", "403 Forbidden");

/**
 * The request is missing a required parameter, includes an unsupported
 * parameter or parameter value, or is otherwise malformed.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3.1
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.2.1
 */
define("OAUTH2_ERROR_INVALID_REQUEST", "invalid_request");

/**
 * The client identifier provided is invalid.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3.1
 */
define("OAUTH2_ERROR_INVALID_CLIENT", "invalid_client");

/**
 * The client is not authorized to use the requested response type.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3.1
 */
define("OAUTH2_ERROR_UNAUTHORIZED_CLIENT", "unauthorized_client");

/**
 * The redirection URI provided does not match a pre-registered value.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 */
define("OAUTH2_ERROR_REDIRECT_URI_MISMATCH", "redirect_uri_mismatch");

/**
 * The end-user or authorization server denied the request.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 */
define("OAUTH2_ERROR_USER_DENIED", "access_denied");

/**
 * The requested response type is not supported by the authorization server.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 */
define("OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE", "unsupported_response_type");

/**
 * The requested scope is invalid, unknown, or malformed.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3.1
 */
define("OAUTH2_ERROR_INVALID_SCOPE", "invalid_scope");

/**
 * The provided access grant is invalid, expired, or revoked (e.g. invalid
 * assertion, expired authorization token, bad end-user password credentials,
 * or mismatching authorization code and redirection URI).
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3.1
 */
define("OAUTH2_ERROR_INVALID_GRANT", "invalid_grant");

/**
 * The access grant included - its type or another attribute - is not
 * supported by the authorization server.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3.1
 */
define("OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE", "unsupported_grant_type");

/**
 * The access token provided is invalid. Resource servers SHOULD use this
 * error code when receiving an expired token which cannot be refreshed to
 * indicate to the client that a new authorization is necessary. The resource
 * server MUST respond with the HTTP 401 (Unauthorized) status code.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.2.1
 */
define("OAUTH2_ERROR_INVALID_TOKEN", "invalid_token");

/**
 * The access token provided has expired. Resource servers SHOULD only use
 * this error code when the client is expected to be able to handle the
 * response and request a new access token using the refresh token issued
 * with the expired access token. The resource server MUST respond with the
 * HTTP 401 (Unauthorized) status code.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.2.1
 */
define("OAUTH2_ERROR_EXPIRED_TOKEN", "expired_token");

/**
 * The request requires higher privileges than provided by the access token.
 * The resource server SHOULD respond with the HTTP 403 (Forbidden) status
 * code and MAY include the "scope" attribute with the scope necessary to
 * access the protected resource.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-5.2.1
 */
define("OAUTH2_ERROR_INSUFFICIENT_SCOPE", "insufficient_scope");

/**
 * Whether to show verbose error messages in the JSON response.
 */
define("OAUTH2_ERROR_VERBOSE", TRUE);

/**
 * @}
 */


abstract class OAuth2 {

  /* Subclasses must implement the following functions */

  // Make sure that the client id is valid
  // If a secret is required, check that they've given the right one
  // Must return FALSE if the client credentials are invalid
  abstract protected function checkClientCredentials($client_id, $client_secret = NULL);

  // OAuth says we should store request URIs for each registered client
  // Implement this function to grab the stored URI for a given client id
  // Must return FALSE if the given client does not exist or is invalid
  abstract protected function getRedirectUri($client_id);

  // We need to store and retrieve access token data as we create and verify tokens
  // Implement these functions to do just that

  // Look up the supplied token id from storage, and return an array like:
  //
  // array(
  //   "client_id" => <stored client id>,
  //   "expires" => <stored expiration timestamp>,
  //   "scope" => <stored scope (may be NULL)
  // )
  //
  // Return NULL if the supplied token is invalid
  //
  abstract protected function getAccessToken($oauth_token);

  // Store the supplied values
  abstract protected function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL);

  /*
   *
   * Stuff that should get overridden by subclasses
   *
   * I don't want to make these abstract, because then subclasses would have
   * to implement all of them, which is too much work.
   *
   * So they're just stubs.  Override the ones you need.
   *
   */

  // You should override this function with something,
  // or else your OAuth provider won't support any grant types!
  protected function getSopportedGrantTypes() {
    // If you support all grant types, then you'd do:
    // return array(
    //   OAUTH2_GRANT_TYPE_AUTH_CODE,
    //   OAUTH2_GRANT_TYPE_USER_CREDENTIALS,
    //   OAUTH2_GRANT_TYPE_ASSERTION,
    //   OAUTH2_GRANT_TYPE_REFRESH_TOKEN,
    //   OAUTH2_GRANT_TYPE_NONE
    // );

    return array();
  }

  // You should override this function with your supported response types
  protected function getSupportedAuthResponseTypes() {
    return array(
      OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE,
      OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN,
      OAUTH2_AUTH_RESPONSE_TYPE_CODE_AND_TOKEN
    );
  }

  // If you want to support scope use, then have this function return a list
  // of all acceptable scopes (used to throw the invalid-scope error)
  protected function getSupportedScopes() {
    // Example:
    // return array("my-friends", "photos", "whatever-else");
    return array();
  }

  // If you want to restrict clients to certain authorization response types,
  // override this function
  // Given a client identifier and auth type, return TRUE or FALSE
  // (auth type would be one of the values contained in OAUTH2_AUTH_RESPONSE_TYPE_REGEXP)
  protected function checkRestrictedClientResponseTypes($client_id, $response_type) {
    return TRUE;
  }

  // If you want to restrict clients to certain grant types, override this function
  // Given a client identifier and grant type, return TRUE or FALSE
  protected function checkRestrictedClientGrantTypes($client_id, $grant_type) {
    return TRUE;
  }

  /* Functions that help grant access tokens for various grant types */

  // Fetch authorization code data (probably the most common grant type)
  // IETF Draft 4.1.1: http://tools.ietf.org/html/draft-ietf-oauth-v2-08#section-4.1.1
  // Required for OAUTH2_GRANT_TYPE_AUTH_CODE
  protected function getAuthCode($code) {
    // Retrieve the stored data for the given authorization code
    // Should return:
    //
    // array (
    //   "client_id" => <stored client id>,
    //   "redirect_uri" => <stored redirect URI>,
    //   "expires" => <stored code expiration time>,
    //   "scope" => <stored scope values (space-separated string), or can be omitted if scope is unused>
    // )
    //
    // Return NULL if the code is invalid.

    return NULL;
  }

  // Take the provided authorization code values and store them somewhere (db, etc.)
  // Required for OAUTH2_GRANT_TYPE_AUTH_CODE
  protected function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL) {
    // This function should be the storage counterpart to getAuthCode

    // If storage fails for some reason, we're not currently checking
    // for any sort of success/failure, so you should bail out of the
    // script and provide a descriptive fail message
  }

  // Grant access tokens for basic user credentials
  // IETF Draft 4.1.2: http://tools.ietf.org/html/draft-ietf-oauth-v2-08#section-4.1.2
  // Required for OAUTH2_GRANT_TYPE_USER_CREDENTIALS
  protected function checkUserCredentials($client_id, $username, $password) {
    // Check the supplied username and password for validity
    // You can also use the $client_id param to do any checks required
    // based on a client, if you need that
    // If the username and password are invalid, return FALSE

    // If the username and password are valid, and you want to verify the scope of
    // a user's access, return an array with the scope values, like so:
    //
    // array (
    //  "scope" => <stored scope values (space-separated string)>
    // )
    //
    // We'll check the scope you provide against the requested scope before
    // providing an access token.
    //
    // Otherwise, just return TRUE.

    return FALSE;
  }

  // Grant access tokens for assertions
  // IETF Draft 4.1.3: http://tools.ietf.org/html/draft-ietf-oauth-v2-08#section-4.1.3
  // Required for OAUTH2_GRANT_TYPE_ASSERTION
  protected function checkAssertion($client_id, $assertion_type, $assertion) {
    // Check the supplied assertion for validity
    // You can also use the $client_id param to do any checks required
    // based on a client, if you need that
    // If the assertion is invalid, return FALSE

    // If the assertion is valid, and you want to verify the scope of
    // an access request, return an array with the scope values, like so:
    //
    // array (
    //  "scope" => <stored scope values (space-separated string)>
    // )
    //
    // We'll check the scope you provide against the requested scope before
    // providing an access token.
    //
    // Otherwise, just return TRUE.

    return FALSE;
  }

  // Grant refresh access tokens
  // IETF Draft 4.1.4: http://tools.ietf.org/html/draft-ietf-oauth-v2-08#section-4.1.4
  // Required for OAUTH2_GRANT_TYPE_REFRESH_TOKEN
  protected function getRefreshToken($refresh_token) {
    // Retrieve the stored data for the given refresh token
    // Should return:
    //
    // array (
    //  "client_id" => <stored client id>,
    //  "expires" => <refresh token expiration time>,
    //  "scope" => <stored scope values (space-separated string), or can be omitted if scope is unused>
    // )
    //
    // Return NULL if the token id is invalid.

    return NULL;
  }

  // Store refresh access tokens
  // Required for OAUTH2_GRANT_TYPE_REFRESH_TOKEN
  protected function setRefreshToken($token, $client_id, $expires, $scope = NULL) {
    // If storage fails for some reason, we're not currently checking
    // for any sort of success/failure, so you should bail out of the
    // script and provide a descriptive fail message

    return;
  }

  private $old_refresh_token = '';

  // Expire a used refresh token.
  // This is not explicitly required in the spec, but is almost implied. After granting a new refresh token,
  // the old one is no longer useful and so should be forcibly expired in the data store so it can't be used again.
  protected function expirseRefreshToken($token) {
    // If storage fails for some reason, we're not currently checking
    // for any sort of success/failure, so you should bail out of the
    // script and provide a descriptive fail message

    return;
  }

  // Grant access tokens for the "none" grant type
  // Not really described in the IETF Draft, so I just left a method stub...do whatever you want!
  // Required for OAUTH2_GRANT_TYPE_NONE
  protected function checkNoneAccess($client_id) {
    return FALSE;
  }

  protected function getDefaultAuthenticationRealm() {
    // Change this to whatever authentication realm you want to send in a WWW-Authenticate header
    return "Service";
  }

  /* End stuff that should get overridden */

  private $access_token_lifetime = 3600;
  private $auth_code_lifetime = 30;
  private $refresh_token_lifetime = 1209600; // Two weeks

  public function __construct($access_token_lifetime = 3600, $auth_code_lifetime = 30, $refresh_token_lifetime = 1209600) {
    $this->access_token_lifetime = $access_token_lifetime;
    $this->auth_code_lifetime = $auth_code_lifetime;
    $this->refresh_token_lifetime = $refresh_token_lifetime;
  }

  /* Resource protecting (Section 5) */

  // Check that a valid access token has been provided
  //
  // The scope parameter defines any required scope that the token must have
  // If a scope param is provided and the token does not have the required scope,
  // we bounce the request
  //
  // Some implementations may choose to return a subset of the protected resource
  // (i.e. "public" data) if the user has not provided an access token
  // or if the access token is invalid or expired
  //
  // The IETF spec says that we should send a 401 Unauthorized header and bail immediately
  // so that's what the defaults are set to
  //
  // Here's what each parameter does:
  // $scope = A space-separated string of required scope(s), if you want to check for scope
  // $exit_not_present = If TRUE and no access token is provided, send a 401 header and exit, otherwise return FALSE
  // $exit_invalid = If TRUE and the implementation of getAccessToken returns NULL, exit, otherwise return FALSE
  // $exit_expired = If TRUE and the access token has expired, exit, otherwise return FALSE
  // $exit_scope = If TRUE the access token does not have the required scope(s), exit, otherwise return FALSE
  // $realm = If you want to specify a particular realm for the WWW-Authenticate header, supply it here
  public function verifyAccessToken($scope = NULL, $exit_not_present = TRUE, $exit_invalid = TRUE, $exit_expired = TRUE, $exit_scope = TRUE, $realm = NULL) {
    $token_param = $this->getAccessTokenParams();
    if ($token_param === FALSE) // Access token was not provided
      return $exit_not_present ? $this->send401Unauthorized($realm, $scope) : FALSE;

    // Get the stored token data (from the implementing subclass)
    $token = $this->getAccessToken($token_param);
    if ($token === NULL)
      return $exit_invalid ? $this->send401Unauthorized($realm, $scope, OAUTH2_ERROR_INVALID_TOKEN) : FALSE;

    // Check token expiration (I'm leaving this check separated, later we'll fill in better error messages)
    if (isset($token["expires"]) && time() > $token["expires"])
      return $exit_expired ? $this->send401Unauthorized($realm, $scope, OAUTH2_ERROR_EXPIRED_TOKEN) : FALSE;

    // Check scope, if provided
    // If token doesn't have a scope, it's NULL/empty, or it's insufficient, then throw an error
    if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->checkScope($scope, $token["scope"])))
      return $exit_scope ? $this->send401Unauthorized($realm, $scope, OAUTH2_ERROR_INSUFFICIENT_SCOPE) : FALSE;

    return TRUE;
  }

  // Returns TRUE if everything in required scope is contained in available scope
  // False if something in required scope is not in available scope
  private function checkScope($required_scope, $available_scope) {
    // The required scope should match or be a subset of the available scope
    if (!is_array($required_scope))
      $required_scope = explode(" ", $required_scope);

    if (!is_array($available_scope))
      $available_scope = explode(" ", $available_scope);

    return (count(array_diff($required_scope, $available_scope)) == 0);
  }

  // Send a 401 unauthorized header with the given realm
  // and an error, if provided
  private function send401Unauthorized($realm, $scope, $error = NULL) {
    $realm = $realm === NULL ? $this->getDefaultAuthenticationRealm() : $realm;

    $auth_header = "WWW-Authenticate: Token realm='" . $realm . "'";

    if ($scope)
      $auth_header .= ", scope='" . $scope . "'";

    if ($error !== NULL)
      $auth_header .= ", error='" . $error . "'";

    header("HTTP/1.1 401 Unauthorized");
    header($auth_header);

    exit;
  }

  // Pulls the access token out of the HTTP request
  // Either from the Authorization header or GET/POST/etc.
  // Returns FALSE if no token is present
  // TODO: Support POST or DELETE
  private function getAccessTokenParams() {
    $auth_header = $this->getAuthorizationHeader();

    if ($auth_header !== FALSE) {
      // Make sure only the auth header is set
      if (isset($_GET[OAUTH2_TOKEN_PARAM_NAME]) || isset($_POST[OAUTH2_TOKEN_PARAM_NAME]))
        $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST, 'Auth token found in GET or POST when token present in header');

      $auth_header = trim($auth_header);

      // Make sure it's Token authorization
      if (strcmp(substr($auth_header, 0, 6), "Token ") !== 0)
        $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST, 'Auth header found that doesn\'t start with "Token"');

      // Parse the rest of the header
      if (preg_match('/\s*token\s*="(.+)"/', substr($auth_header, 6), $matches) == 0 || count($matches) < 2)
        $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST, 'Malformed auth header');

      return $matches[1];
    }

    if (isset($_GET[OAUTH2_TOKEN_PARAM_NAME]))  {
      if (isset($_POST[OAUTH2_TOKEN_PARAM_NAME])) // Both GET and POST are not allowed
        $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST, 'Only send the token in GET or POST, not both');

      return $_GET[OAUTH2_TOKEN_PARAM_NAME];
    }

    if (isset($_POST[OAUTH2_TOKEN_PARAM_NAME]))
      return $_POST[OAUTH2_TOKEN_PARAM_NAME];

    return FALSE;
  }

  /* Access token granting (Section 4) */

  // Grant or deny a requested access token
  // This would be called from the "/token" endpoint as defined in the spec
  // Obviously, you can call your endpoint whatever you want
  public function grantAccessToken() {
    $filters = array(
      "grant_type" => array("filter" => FILTER_VALIDATE_REGEXP, "options" => array("regexp" => OAUTH2_GRANT_TYPE_REGEXP), "flags" => FILTER_REQUIRE_SCALAR),
      "scope" => array("flags" => FILTER_REQUIRE_SCALAR),
      "code" => array("flags" => FILTER_REQUIRE_SCALAR),
      "redirect_uri" => array("filter" => FILTER_SANITIZE_URL),
      "username" => array("flags" => FILTER_REQUIRE_SCALAR),
      "password" => array("flags" => FILTER_REQUIRE_SCALAR),
      "assertion_type" => array("flags" => FILTER_REQUIRE_SCALAR),
      "assertion" => array("flags" => FILTER_REQUIRE_SCALAR),
      "refresh_token" => array("flags" => FILTER_REQUIRE_SCALAR),
    );

    $input = filter_input_array(INPUT_POST, $filters);

    // Grant Type must be specified.
    if (!$input["grant_type"])
      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST, 'Invalid grant_type parameter or parameter missing');

    // Make sure we've implemented the requested grant type
    if (!in_array($input["grant_type"], $this->getSopportedGrantTypes()))
      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE);

    // Authorize the client
    $client = $this->getClientCredentials();

    if ($this->checkClientCredentials($client[0], $client[1]) === FALSE)
      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_CLIENT);

    if (!$this->checkRestrictedClientGrantTypes($client[0], $input["grant_type"]))
      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_UNAUTHORIZED_CLIENT);

    // Do the granting
    switch ($input["grant_type"]) {
      case OAUTH2_GRANT_TYPE_AUTH_CODE:
        if (!$input["code"] || !$input["redirect_uri"])
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST);

        $stored = $this->getAuthCode($input["code"]);

        // Ensure that the input uri starts with the stored uri
        if ($stored === NULL || (strcasecmp(substr($input["redirect_uri"], 0, strlen($stored["redirect_uri"])), $stored["redirect_uri"]) !== 0) || $client[0] != $stored["client_id"])
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_GRANT);

        if ($stored["expires"] < time())
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_EXPIRED_TOKEN);

        break;
      case OAUTH2_GRANT_TYPE_USER_CREDENTIALS:
        if (!$input["username"] || !$input["password"])
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST, 'Missing parameters. "username" and "password" required');

        $stored = $this->checkUserCredentials($client[0], $input["username"], $input["password"]);

        if ($stored === FALSE)
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_GRANT);

        break;
      case OAUTH2_GRANT_TYPE_ASSERTION:
        if (!$input["assertion_type"] || !$input["assertion"])
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST);

        $stored = $this->checkAssertion($client[0], $input["assertion_type"], $input["assertion"]);

        if ($stored === FALSE)
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_GRANT);

        break;
      case OAUTH2_GRANT_TYPE_REFRESH_TOKEN:
        if (!$input["refresh_token"])
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST, 'No "refresh_token" parameter found');

        $stored = $this->getRefreshToken($input["refresh_token"]);

        if ($stored === NULL || $client[0] != $stored["client_id"])
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_GRANT);

        if ($stored["expires"] < time())
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_EXPIRED_TOKEN);

        // store the refresh token locally so we can delete it when a new refresh token is generated
        $this->old_refresh_token = $stored["token"];

        break;
      case OAUTH2_GRANT_TYPE_NONE:
        $stored = $this->checkNoneAccess($client[0]);

        if ($stored === FALSE)
          $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST);
    }

    // Check scope, if provided
    if ($input["scope"] && (!is_array($stored) || !isset($stored["scope"]) || !$this->checkScope($input["scope"], $stored["scope"])))
      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_SCOPE);

    if (!$input["scope"])
      $input["scope"] = NULL;

    $token = $this->createAccessToken($client[0], $input["scope"]);

    $this->sendJsonHeaders();
    echo json_encode($token);
  }

  // Internal function used to get the client credentials from HTTP basic auth or POST data
  // See http://tools.ietf.org/html/draft-ietf-oauth-v2-08#section-2
  protected function getClientCredentials() {
    if (isset($_SERVER["PHP_AUTH_USER"]) && $_POST && isset($_POST["client_id"]))
      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_CLIENT);

    // Try basic auth
    if (isset($_SERVER["PHP_AUTH_USER"]))
      return array($_SERVER["PHP_AUTH_USER"], $_SERVER["PHP_AUTH_PW"]);

    // Try POST
    if ($_POST && isset($_POST["client_id"])) {
      if (isset($_POST["client_secret"]))
        return array($_POST["client_id"], $_POST["client_secret"]);

      return array($_POST["client_id"], NULL);
    }

    // No credentials were specified
    $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_CLIENT);
  }

  /* End-user/client Authorization (Section 3 of IETF Draft) */

  // Pull the authorization request data out of the HTTP request
  // and return it so the authorization server can prompt the user
  // for approval
  public function getAuthorizeParams() {
    $filters = array(
      "client_id" => array("filter" => FILTER_VALIDATE_REGEXP, "options" => array("regexp" => OAUTH2_CLIENT_ID_REGEXP), "flags" => FILTER_REQUIRE_SCALAR),
      "response_type" => array("filter" => FILTER_VALIDATE_REGEXP, "options" => array("regexp" => OAUTH2_AUTH_RESPONSE_TYPE_REGEXP), "flags" => FILTER_REQUIRE_SCALAR),
      "redirect_uri" => array("filter" => FILTER_SANITIZE_URL),
      "state" => array("flags" => FILTER_REQUIRE_SCALAR),
      "scope" => array("flags" => FILTER_REQUIRE_SCALAR),
    );

    $input = filter_input_array(INPUT_GET, $filters);

    // Make sure a valid client id was supplied
    if (!$input["client_id"]) {
      if ($input["redirect_uri"])
        $this->errorCallback($input["redirect_uri"], OAUTH2_ERROR_INVALID_CLIENT, $input["state"]);

      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_CLIENT); // We don't have a good URI to use
    }

    // redirect_uri is not required if already established via other channels
    // check an existing redirect URI against the one supplied
    $redirect_uri = $this->getRedirectUri($input["client_id"]);

    // At least one of: existing redirect URI or input redirect URI must be specified
    if (!$redirect_uri && !$input["redirect_uri"])
      $this->error(OAUTH2_ERROR_HTTP_BAD_REQUEST, OAUTH2_ERROR_INVALID_REQUEST);

    // getRedirectUri should return FALSE if the given client ID is invalid
    // this probably saves us from making a separate db call, and simplifies the method set
    if ($redirect_uri === FALSE)
      $this->errorCallback($input["redirect_uri"], OAUTH2_ERROR_INVALID_CLIENT, $input["state"]);

    // If there's an existing uri and one from input, verify that they match
    if ($redirect_uri && $input["redirect_uri"]) {
      // Ensure that the input uri starts with the stored uri
      if (strcasecmp(substr($input["redirect_uri"], 0, strlen($redirect_uri)), $redirect_uri) !== 0)
        $this->errorCallback($input["redirect_uri"], OAUTH2_ERROR_REDIRECT_URI_MISMATCH, $input["state"]);
    }
    elseif ($redirect_uri) { // They did not provide a uri from input, so use the stored one
      $input["redirect_uri"] = $redirect_uri;
    }

    // type and client_id are required
    if (!$input["response_type"])
      $this->errorCallback($input["redirect_uri"], OAUTH2_ERROR_INVALID_REQUEST, $input["state"]);

    // Check requested auth response type against the list of supported types
    if (array_search($input["response_type"], $this->getSupportedAuthResponseTypes()) === FALSE)
      $this->errorCallback($input["redirect_uri"], OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE, $input["state"]);

    // Restrict clients to certain authorization response types
    if ($this->checkRestrictedClientResponseTypes($input["client_id"], $input["response_type"]) === FALSE)
      $this->errorCallback($input["redirect_uri"], OAUTH2_ERROR_UNAUTHORIZED_CLIENT, $input["state"]);

    // Validate that the requested scope is supported
    if ($input["scope"] && !$this->checkScope($input["scope"], $this->getSupportedScopes()))
      $this->errorCallback($input["redirect_uri"], OAUTH2_ERROR_INVALID_SCOPE, $input["state"]);

    return $input;
  }

  // After the user has approved or denied the access request
  // the authorization server should call this function to redirect
  // the user appropriately

  // The params all come from the results of getAuthorizeParams
  // except for $is_authorized -- this is TRUE or FALSE depending on whether
  // the user authorized the access
  public function finishClientAuthorization($is_authorized, $type, $client_id, $redirect_uri, $state, $scope = NULL) {
    if ($state !== NULL)
      $result["query"]["state"] = $state;

    if ($is_authorized === FALSE) {
      $result["query"]["error"] = OAUTH2_ERROR_USER_DENIED;
    }
    else {
      if ($type == OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE || $type == OAUTH2_AUTH_RESPONSE_TYPE_CODE_AND_TOKEN)
        $result["query"]["code"] = $this->createAuthCode($client_id, $redirect_uri, $scope);

      if ($type == OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN || $type == OAUTH2_AUTH_RESPONSE_TYPE_CODE_AND_TOKEN)
        $result["fragment"] = $this->createAccessToken($client_id, $scope);
    }

    $this->doRedirectUriCallback($redirect_uri, $result);
  }

  /* Other/utility functions */

  private function doRedirectUriCallback($redirect_uri, $result) {
    header("HTTP/1.1 302 Found");
    header("Location: " . $this->buildUri($redirect_uri, $result));
    exit;
  }

  private function buildUri($uri, $data) {
    $parse_url = parse_url($uri);

    // Add our data to the parsed uri
    foreach ($data as $k => $v) {
      if (isset($parse_url[$k]))
        $parse_url[$k] .= "&" . http_build_query($v);
      else
        $parse_url[$k] = http_build_query($v);
    }

    // Put humpty dumpty back together
    return
      ((isset($parse_url["scheme"])) ? $parse_url["scheme"] . "://" : "")
      . ((isset($parse_url["user"])) ? $parse_url["user"] . ((isset($parse_url["pass"])) ? ":" . $parse_url["pass"] : "") . "@" : "")
      . ((isset($parse_url["host"])) ? $parse_url["host"] : "")
      . ((isset($parse_url["port"])) ? ":" . $parse_url["port"] : "")
      . ((isset($parse_url["path"])) ? $parse_url["path"] : "")
      . ((isset($parse_url["query"])) ? "?" . $parse_url["query"] : "")
      . ((isset($parse_url["fragment"])) ? "#" . $parse_url["fragment"] : "");
  }

  // This belongs in a separate factory, but to keep it simple, I'm just keeping it here.
  protected function createAccessToken($client_id, $scope) {
    $token = array(
      "access_token" => $this->genAccessToken(),
      "expires_in" => $this->access_token_lifetime,
      "scope" => $scope
    );

    $this->setAccessToken($token["access_token"], $client_id, time() + $this->access_token_lifetime, $scope);

    // Issue a refresh token also, if we support them
    if (in_array(OAUTH2_GRANT_TYPE_REFRESH_TOKEN, $this->getSopportedGrantTypes())) {
      $token["refresh_token"] = $this->genAccessToken();
      $this->setRefreshToken($token["refresh_token"], $client_id, time() + $this->refresh_token_lifetime, $scope);
      // If we've granted a new refresh token, expire the old one
      if ($this->old_refresh_token)
        $this->expirseRefreshToken($this->old_refresh_token);
    }

    return $token;
  }

  private function createAuthCode($client_id, $redirect_uri, $scope) {
    $code = $this->genAuthCode();
    $this->setAuthCode($code, $client_id, $redirect_uri, time() + $this->auth_code_lifetime, $scope);
    return $code;
  }

  // Implementing classes may want to override these two functions
  // to implement other access token or auth code generation schemes
  protected function genAccessToken() {
    return base64_encode(pack('N6', mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand()));
  }

  protected function genAuthCode() {
    return base64_encode(pack('N6', mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand()));
  }

  // Implementing classes may need to override this function for use on non-Apache web servers
  // Just pull out the Authorization HTTP header and return it
  // Return FALSE if the Authorization header does not exist
  private function getAuthorizationHeader() {
    if (array_key_exists("HTTP_AUTHORIZATION", $_SERVER))
      return $_SERVER["HTTP_AUTHORIZATION"];

    if (function_exists("apache_request_headers")) {
      $headers = apache_request_headers();

      if (array_key_exists("Authorization", $headers))
        return $headers["Authorization"];
    }

    return FALSE;
  }

  private function sendJsonHeaders() {
    header("Content-Type: application/json");
    header("Cache-Control: no-store");
  }

  public function error($http_status_code, $error = NULL, $error_description = NULL, $error_uri = NULL) {
    header("HTTP/1.1 " . $http_status_code);

    if ($error) {
      $this->sendJsonHeaders();

      $result['error'] = $error;

      if (OAUTH2_ERROR_VERBOSE && $error_description)
        $result["error_description"] = $error_description;

      if (OAUTH2_ERROR_VERBOSE && $error_uri)
        $result["error_uri"] = $error_uri;

      echo json_encode($result);
    }

    exit;
  }

  public function errorCallback($redirect_uri, $error, $state, $error_description = NULL, $error_uri = NULL) {
    $result["query"]["error"] = $error;

    if ($state)
      $result["query"]["state"] = $state;

    if (OAUTH2_ERROR_VERBOSE && $error_description)
      $result["query"]["error_description"] = $error_description;

    if (OAUTH2_ERROR_VERBOSE && $error_uri)
      $result["query"]["error_uri"] = $error_uri;

    $this->doRedirectUriCallback($redirect_uri, $result);
  }
}
