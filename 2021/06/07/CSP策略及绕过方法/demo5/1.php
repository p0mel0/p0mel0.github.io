<?php header("X-XSS-Protection:0");?>
<meta http-equiv="Content-Security-Policy" content= "default-src 'self';script-src 'nonce-xxxxx'">
<?php echo $_POST['xss']?>
<script nonce='xxxxx'>
  //do some thing
</script>	