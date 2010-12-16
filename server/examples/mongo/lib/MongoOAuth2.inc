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
    public function add_client($client_id, $client_secret, $redirect_uri) {
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
    protected function auth_client_credentials($client_id, $client_secret = null) {
        $client = $this->db->clients->findOne(array("_id" => $client_id, "pw" =>  $client_secret));
        return $client !== null;
    }

    protected function get_redirect_uri($client_id) {
        $uri = $this->db->clients->findOne(array("_id" => $client_id), array("redirect_uri"));
        return $uri !== null ? $uri["redirect_uri"] : false;
    }

    protected function get_access_token($oauth_token) {
        return $this->db->tokens->findOne(array("_id" => $oauth_token));
    }

    protected function store_access_token($oauth_token, $client_id, $expires, $scope = null) {
        $this->db->tokens->insert(array(
            "_id" => $oauth_token,
            "client_id" => $client_id,
            "expires" => $expires,
            "scope" => $scope
        ));
    }

    protected function get_supported_grant_types() {
        return array(OAUTH2_GRANT_TYPE_AUTH_CODE);
    }

    protected function get_stored_auth_code($code) {
        $stored_code = $this->db->auth_codes->findOne(array("_id" => $code));
        return $stored_code !== null ? $stored_code : false;
    }

    // Take the provided authorization code values and store them somewhere (db, etc.)
    // Required for OAUTH2_GRANT_TYPE_AUTH_CODE
    protected function store_auth_code($code, $client_id, $redirect_uri, $expires, $scope = null) {
        $this->db->auth_codes->insert(array(
            "_id" => $code,
            "client_id" => $client_id,
            "redirect_uri" => $redirect_uri,
            "expires" => $expires,
            "scope" => $scope
        ));
    }
}
