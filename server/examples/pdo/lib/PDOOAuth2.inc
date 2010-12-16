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
    $this->db = NULL; // Release db connection
  }

  private function handleException($e) {
    echo "Database error: " . $e->getMessage();
    exit;
  }

  // Little helper function to add a new client to the database
  // Do NOT use this in production!  This sample code stores the secret in plaintext!
  public function addClient($client_id, $client_secret, $redirect_uri) {
    try {
      $sql = "INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES (:client_id, :client_secret, :redirect_uri)";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->bindParam(":client_secret", $client_secret, PDO::PARAM_STR);
      $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
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
  protected function checkClientCredentials($client_id, $client_secret = NULL) {
    try {
      $sql = "SELECT client_secret FROM clients WHERE client_id = :client_id";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($client_secret === NULL)
          return $result !== FALSE;

      return $result["client_secret"] == $client_secret;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  protected function getRedirectUri($client_id) {
    try {
      $sql = "SELECT redirect_uri FROM clients WHERE client_id = :client_id";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($result === FALSE)
          return FALSE;

      return isset($result["redirect_uri"]) && $result["redirect_uri"] ? $result["redirect_uri"] : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  protected function getAccessToken($oauth_token) {
    try {
      $sql = "SELECT client_id, expires, scope FROM tokens WHERE oauth_token = :oauth_token";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":oauth_token", $oauth_token, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      return $result !== FALSE ? $result : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  protected function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL) {
    try {
      $sql = "INSERT INTO tokens (oauth_token, client_id, expires, scope) VALUES (:oauth_token, :client_id, :expires, :scope)";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":oauth_token", $oauth_token, PDO::PARAM_STR);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
      $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);

      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  protected function getSopportedGrantTypes() {
    return array(
      OAUTH2_GRANT_TYPE_AUTH_CODE,
    );
  }

  protected function getAuthCode($code) {
    try {
      $sql = "SELECT code, client_id, redirect_uri, expires, scope FROM auth_codes WHERE code = :code";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":code", $code, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      return $result !== FALSE ? $result : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  // Take the provided authorization code values and store them somewhere (db, etc.)
  // Required for OAUTH2_GRANT_TYPE_AUTH_CODE
  protected function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL) {
    try {
      $sql = "INSERT INTO auth_codes (code, client_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :redirect_uri, :expires, :scope)";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":code", $code, PDO::PARAM_STR);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
      $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
      $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);

      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }
}
