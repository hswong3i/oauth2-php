<?php

/*
 *
 * Sample OAuth2 Library PDO DB Implementation
 *
 */

// Set these values to your database access info
define("PDO_DSN", "mysql:dbname=mydb;host=localhost");
define("PDO_USER", "user");
define("PDO_PASS", "pass");

include "../../../lib/oauth.php";

class PDOOAuth2 extends OAuth2 {
    private $db;

    public function __construct() {
        parent::__construct();

        try {
            $this->db = new PDO(PDO_DSN, PDO_USER, PDO_PASS);
        } catch (PDOException $e) {
            die('Connection failed: ' . $e->getMessage());
        }
    }

    function __destruct() {
        $this->db = null; // Release db connection
    }

    private function handle_exception($e) {
        echo "Database error: " . $e->getMessage();
        exit;
    }

    // Little helper function to add a new client to the database
    // Do NOT use this in production!  This sample code stores the secret in plaintext!
    public function add_client($client_id, $client_secret, $redirect_uri) {
        try {
            $sql = "insert into clients (client_id, client_secret, redirect_uri) values (:client_id, :client_secret, :redirect_uri)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->bindParam(":client_secret", $client_secret, PDO::PARAM_STR);
            $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            $this->handle_exception($e);
        }
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
        try {
            $sql = "select client_secret from clients where client_id = :client_id";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($client_secret === null)
                return $result !== false;

            return $result["client_secret"] == $client_secret;
        } catch (PDOException $e) {
            $this->handle_exception($e);
        }
    }

    protected function get_redirect_uri($client_id) {
        try {
            $sql = "select redirect_uri from clients where client_id = :client_id";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($result === false)
                return false;

            return isset($result["redirect_uri"]) && $result["redirect_uri"] ? $result["redirect_uri"] : null;
        } catch (PDOException $e) {
            $this->handle_exception($e);
        }
    }

    protected function get_access_token($oauth_token) {
        try {
            $sql = "select client_id, expires, scope from tokens where oauth_token = :oauth_token";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":oauth_token", $oauth_token, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result !== false ? $result : null;
        } catch (PDOException $e) {
            $this->handle_exception($e);
        }
    }

    protected function store_access_token($oauth_token, $client_id, $expires, $scope = null) {
        try {
            $sql = "insert into tokens (oauth_token, client_id, expires, scope) values (:oauth_token, :client_id, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":oauth_token", $oauth_token, PDO::PARAM_STR);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
            $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handle_exception($e);
        }
    }

    protected function get_supported_grant_types() {
        return array(AUTH_CODE_GRANT_TYPE);
    }

    protected function get_stored_auth_code($code) {
        try {
            $sql = "select code, client_id, redirect_uri, expires, scope from auth_codes where code = :code";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":code", $code, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result !== false ? $result : null;
        } catch (PDOException $e) {
            $this->handle_exception($e);
        }
    }

    // Take the provided authorization code values and store them somewhere (db, etc.)
    // Required for AUTH_CODE_GRANT_TYPE
    protected function store_auth_code($code, $client_id, $redirect_uri, $expires, $scope = null) {
        try {
            $sql = "insert into auth_codes (code, client_id, redirect_uri, expires, scope) values (:code, :client_id, :redirect_uri, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":code", $code, PDO::PARAM_STR);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
            $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
            $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handle_exception($e);
        }
    }
}
