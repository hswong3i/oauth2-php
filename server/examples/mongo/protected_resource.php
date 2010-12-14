<?php
/*
 *
 * Sample protected resource
 * Obviously not production-ready code, just simple and to the point.
 * In reality, you'd probably use a nifty framework to handle most of the crud for you.
 *
 */

require "lib/MongoOAuth2.inc";

$oauth = new MongoOAuth2();
$oauth->verify_access_token();

// With a particular scope, you'd do:
// $oauth->verify_access_token("scope_name");

?>

<html>
    <head>
        <title>Hello!</title>
    </head>
    <body>
        <p>This is a secret.</p>
    </body>
</html>
