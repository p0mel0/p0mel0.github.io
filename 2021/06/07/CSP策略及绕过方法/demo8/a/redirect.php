<!-- redirect.php -->
<?php
 header("Content-Security-Policy: default-src 'self';script-src http://localhost/CSP/demo7/a/");
header("Location: " . $_GET[url]);
?>