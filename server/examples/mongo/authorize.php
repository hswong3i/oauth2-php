<?php
/*
 *
 * Sample authorize endpoint
 * Obviously not production-ready code, just simple and to the point.
 * In reality, you'd probably use a nifty framework to handle most of the crud for you.
 *
 */

require "lib/MongoOAuth2.inc";

$oauth = new MongoOAuth2();

if ($_POST) {
    $is_authorized = $_POST["accept"] == "Yep";
    $type = $_POST["response_type"];
    $client_id = $_POST["client_id"];
    $redirect_uri = $_POST["redirect_uri"];
    $state = $_POST["state"];
    $scope = $_POST["scope"];

    $oauth->finish_client_authorization($is_authorized, $type, $client_id, $redirect_uri, $state, $scope);
}

$auth_params = $oauth->get_authorize_params();

?>
<html>
    <head>Authorize</head>
    <body>
        <form method="post" action="authorize.php">
            <?php foreach ($auth_params as $k => $v) { ?>
            <input type="hidden" name="<?php echo $k ?>" value="<?php echo $v ?>" />
            <?php } ?>

            Do you authorize the app to do its thing?
            <p>
                <input type="submit" name="accept" value="Yep" />
                <input type="submit" name="accept" value="Nope" />
            </p>
        </form>
    </body>
</html>
