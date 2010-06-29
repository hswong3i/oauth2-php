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

include "oauth.php";

class MongoOAuth2 extends OAuth2 {
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

    // Little helper function to add a new client to the database
    // Do NOT use this in production!  This sample code stores the secret in plaintext!
    public function add_client($client_id, $secret, $redirect_uri) {
        try {
            $sql = "insert into clients (client_id, pw, redirect_uri) values (:client_id, :pw, :redirect_uri)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->bindParam(":pw", $pw, PDO::PARAM_STR);
            $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            echo "Database error: " . $e->getMessage();
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
            $sql = "select pw from clients where client_id = :client_id";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($client_secret === null)
                return $result !== false;

            return $result["pw"] == $client_secret;
        } catch (PDOException $e) {
            echo "Database error: " . $e->getMessage();
        }
    }

    protected function get_redirect_uri($client_id) {
        try {
            $sql = "select redirect_uri from clients where client_id = :client_id";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result !== false && isset($result["redirect_uri"]) && $result["redirect_uri"] ? $result["redirect_uri"] : null;
        } catch (PDOException $e) {
            echo "Database error: " . $e->getMessage();
        }
    }

    protected function get_access_token($token_id) {
        try {
            $sql = "select client_id, expires, scope from tokens where id = :client_id";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result !== false ? $result : null;
        } catch (PDOException $e) {
            echo "Database error: " . $e->getMessage();
        }
    }

    protected function store_access_token($token_id, $client_id, $expires, $scope = null) {
        try {
            $sql = "insert into tokens (id, client_id, expires, scope) values (:id, :client_id, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":id", $token_id, PDO::PARAM_STR);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
            $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            echo "Database error: " . $e->getMessage();
        }
    }

    protected function get_supported_grant_types() {
        return array(AUTH_CODE_GRANT_TYPE);
    }

    protected function get_stored_auth_code($code) {
        $sql = "select id, client_id, redirect_uri, expires, scope from auth_codes where id = :id";
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(":id", $code, PDO::PARAM_STR);
        $stmt->execute;

        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result !== false ? $result : null;
    }

    // Take the provided authorization code values and store them somewhere (db, etc.)
    // Required for AUTH_CODE_GRANT_TYPE
    protected function store_auth_code($code, $client_id, $redirect_uri, $expires, $scope) {
        try {
            $sql = "insert into auth_codes (id, client_id, redirect_uri, expires, scope) values (:id, :client_id, :redirect_uri, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(":id", $code, PDO::PARAM_STR);
            $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
            $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
            $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
            $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            echo "Database error: " . $e->getMessage();
        }
    }
}