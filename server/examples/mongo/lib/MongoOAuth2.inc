<?php

/*
 *
 * Sample OAuth2 Library Mongo DB Implementation
 *
 */

// Set these values to your Mongo database
define("MONGO_CONNECTION", "mongodb://user:pass@mongoserver/mydb");
define("MONGO_DB", "mydb");

include "../../../lib/oauth.php";

class MongoOAuth2 extends OAuth2 {
  private $db;

  public function __construct() {
    parent::__construct();

    $mongo = new Mongo(MONGO_CONNECTION);
    $this->db = $mongo->selectDB(MONGO_DB);
  }

  // Do NOT use this in production!  This sample code stores the secret in plaintext!
  public function addClient($client_id, $client_secret, $redirect_uri) {
    $this->db->clients->insert(array(
      "_id" => $client_id,
      "pw" => $client_secret,
      "redirect_uri" => $redirect_uri
    ));
  }

  /*
   *
   * Below, we've implemented the required OAuth2 methods
   * which are either declared as abstract or meant to be
   * overridden in the base class.
   *
   */

  // Do NOT use this in production!  This sample code stores the secret in plaintext!
  protected function checkClientCredentials($client_id, $client_secret = NULL) {
    $client = $this->db->clients->findOne(array("_id" => $client_id, "pw" =>  $client_secret));
    return $client !== NULL;
  }

  protected function getRedirectUri($client_id) {
    $uri = $this->db->clients->findOne(array("_id" => $client_id), array("redirect_uri"));
    return $uri !== NULL ? $uri["redirect_uri"] : FALSE;
  }

  protected function getAccessToken($oauth_token) {
    return $this->db->tokens->findOne(array("_id" => $oauth_token));
  }

  protected function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL) {
    $this->db->tokens->insert(array(
      "_id" => $oauth_token,
      "client_id" => $client_id,
      "expires" => $expires,
      "scope" => $scope
    ));
  }

  protected function getSupportedGrantTypes() {
    return array(
      OAUTH2_GRANT_TYPE_AUTH_CODE,
    );
  }

  protected function getAuthCode($code) {
    $stored_code = $this->db->auth_codes->findOne(array("_id" => $code));
    return $stored_code !== NULL ? $stored_code : FALSE;
  }

  // Take the provided authorization code values and store them somewhere (db, etc.)
  // Required for OAUTH2_GRANT_TYPE_AUTH_CODE
  protected function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL) {
    $this->db->auth_codes->insert(array(
      "_id" => $code,
      "client_id" => $client_id,
      "redirect_uri" => $redirect_uri,
      "expires" => $expires,
      "scope" => $scope
    ));
  }
}
