<?php
    if (!isset($_COOKIE['session'])) {
        setcookie('session',md5(rand(0,1000)));
    }
        header("Content-Security-Policy: script-src 'self';");
?>
<!DOCTYPE html>
<html>
<head>
    <title>CSP Test</title>
</head>
<body>
<h2>CSP-safe</h2>
<?php
    if (isset($_POST['a'])) {
        echo "Your POST content".@$_POST['a'];
    }
?>