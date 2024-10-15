<?php
/**
 * The goal of this file is to password protect other files by a
 * simple
 * @example require('sspasswordprotect.php');
 * Make sure you have a file 'sspp.cfg.php' in the same directory
 * If not logged in, it will attempt
 */
class sspp {
    private static $showLoginBar = true;
    private static $users = array('admin'=>'admin84');

    public static function end(): never{
        ob_end_flush();
        exit;
    }

    public static function no_show_login_bar(){
        self::$showLoginBar = false;
    }

    public static function show_login_bar(){
        self::$showLoginBar = true;
    }

    public static function inject_login_bar(): bool{
        return self::$showLoginBar;
    }


    public static function load_users(){
        if (file_exists('sspp.cfg.php')){
            include('sspp.cfg.php');
            self::$users = $users;
        }else{
            //do not error out, instead allow admin user as listed above
            //die('sspp.config.php does not exist');
            //exit;
        }
    }

    public static function loggedin_user(){
        if (self::isloggedin()){
            return $_SESSION['sspp_loggedin_user'];
        }else{
            return "";
        }
    }

    public static function isloggedin(){
        return  !empty($_SESSION['sspp_loggedin_user']) &&
            !empty(self::$users[$_SESSION['sspp_loggedin_user']]);
    }

    public static function secure(){
        session_start();
        if (!self::isloggedin()){
            header('Location: '.basename(__FILE__).'?login&goto='.urlencode(self::remove_query_key_from_url($_SERVER['REQUEST_URI'],'sspp-logout')));
            exit;
        }
    }

    public static function auth_with_post(){
        if (isset($_POST['user']) && isset($_POST['pw'])){
            return self::auth($_POST['user'], $_POST['pw']);
        }else{
            return 0; //post variables not set
        }
    }

    public static function auth($user, $pw){
        if (isset(self::$users[$user]) && self::$users[$user] == $pw){
            $_SESSION['sspp_loggedin_user'] = $user;
            return true;
        }
        else{
            //failed to authenticate on list of users
            $_SESSION['sspp_auth_error'] = 'Invalid username or password.';
            return false;
        }
    }

    public static function logout(){
        $_SESSION['sspp_loggedin_user'] = 'notloggedin';
        unset($_SESSION['sspp_loggedin_user']);
        session_destroy();
        return empty($_SESSION['sspp_loggedin_user']);
    }


    public static function page_logic(){
        $logout = isset($_GET['sspp-logout']);
        if ($logout){
            session_start();
            sspp::logout();
            if (!empty($_REQUEST['goto'])) {
                $goto = self::remove_query_key_from_url($_REQUEST['goto'], 'sspp-logout');
                header('Location: ' . $goto);
                exit;
            }
        }
        //are we accessing this file directly? if so put a login prompt
        if (basename($_SERVER['PHP_SELF']) == basename(__FILE__)){
            session_start();

            if (isset($_GET['logout'])){
                sspp::logout();
                if (!empty($_GET['goto'])){
                    header('Location: '.$_GET['goto']);
                    exit;
                }else{
                    die("Logged out <a href=\"javascript:history.back();\">Back to previous page</a>");
                }
            }

            if (sspp::isloggedin() || sspp::auth_with_post()){
                if (!empty($_GET['goto'])){
                    header('Location: '.$_GET['goto']);
                    exit;
                }else{
                    die('Logged in!');
                }
            }else{
                sspp::page_protect_with_login();
                exit;
            }
        }else{
            //die($_SERVER['PHP_SELF'].' <br> '.basename(__FILE__));
            //calling from a different page
            sspp::secure();
            return;
            //all code after this (from other files) are accessing protected content;
        }
    }


    public static function page_protect_with_login(){
        $goto = $_GET['goto'];
        $goto = self::remove_query_key_from_url($goto, 'sspp-logout');
        $gotoquery = isset($_GET['goto'])?'?goto='.urlencode($goto) : '';
        ?>
        <!doctype html>
        <html lang="en">
    <head>
        <title>Protected Login - SSPP (Super Simple Password Protection)</title>
        <style>
            body {
                font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif;
            }
            .frmSSPPLogin {
                border: 1px solid silver;
                background-color: #F3FFE1;
                width: 15em;
                padding: .25em 1em;
                text-align: center;
                margin: 0 auto;
            }
            .frmSSPPLogin .form-group {
                margin-bottom: 1em;
                text-align: left;
            }
            .frmSSPPLogin label, .frmSSPPLogin input {
                width: 100%;
                display: block;
            }
            .frmSSPPLogin input {
                margin-top: .25em;
                padding: .5em;
                box-sizing: border-box;
            }
            .error {
                color: red;
            }
            .center {
                margin: 0 auto;
            }
            .info {
                color: #008000;
            }
        </style>
    </head>
    <body>

    <form class="frmSSPPLogin center" action="<?=basename(__FILE__).$gotoquery?>" method="POST">

        <p class="info">This page is password protected you must login in order to continue</p>

        <?php if (isset($_SESSION['sspp_auth_error'])){
            ?><p class="error"><?=$_SESSION['sspp_auth_error']?></p><?php
            unset($_SESSION['sspp_auth_error']); //no need to keep it around
        }
        ?>

        <div class="form-group">
            <label for="user">Username</label>
            <input type="text" name="user" id="user">
        </div>

        <div class="form-group">
            <label for="pw">Password</label>
            <input type="password" name="pw" id="pw">
        </div>

        <button type="submit">Login</button>
    </form>
    </body>
        </html><?php
    }

    public static function remove_query_key_from_url(string $url, string $key): string
    {
        $urlParts = parse_url($url);

        if (!isset($urlParts['query'])) {
            return $url;
        }

        // Parse query string into an associative array
        parse_str($urlParts['query'], $queryParams);

        // Unset the key from the query string parameters
        unset($queryParams[$key]);

        // Rebuild the query string
        $updatedQueryString = http_build_query($queryParams);

        // Reconstruct the final URL
        $newURL = '';

        if (isset($urlParts['scheme'])) {
            $newURL .= $urlParts['scheme'] . '://';
        }

        if (isset($urlParts['host'])) {
            $newURL .= $urlParts['host'];
        }

        if (isset($urlParts['port'])) {
            $newURL .= ':' . $urlParts['port'];
        }

        if (isset($urlParts['path'])) {
            $newURL .= $urlParts['path'];
        }

        if (!empty($updatedQueryString)) {
            $newURL .= '?' . $updatedQueryString;
        }

        if (isset($urlParts['fragment'])) {
            $newURL .= '#' . $urlParts['fragment'];
        }

        return $newURL;
    }

    public static function sspp_css(): string{
        $css = <<<EOT
        .sspp-logout-link {
            text-decoration: none;
            color: #ecf0f1;
            background-color: #e74c3c;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            /*transition: background-color 0.3s ease-in-out;*/
        }
        .sspp-logout-link:hover {
            background-color: #c0392b;
        }
        .sspp-logout-link {
            margin-left: 7px;
            margin-right: 3px;
        }

        .sspp-top-logged-in-bar {
            background-color: #F3FFE1; /* Updated top bar background to a dark gray */
            color: #53973b; /* Kept top bar text color to light */
            padding: 1rem;
            padding-left: 3px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            position: fixed; /* Make the top bar stay fixed at the top */
            width: 100%; /* Ensure the top bar spans the full width of the screen */
            top: 0; /* Position it at the top */
            z-index: 1000; /* Ensure it stays above other elements */
        }

        .sspp-top-logged-in-bar .welcome {
            font-size: 1.7rem;
            margin-left: 15px;
        }
EOT;
        return $css;

    }
}

//Set no caching
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

sspp::load_users();
sspp::page_logic();

$showLoginBar = true;
//everything that gets here is secure.
$outputBuffering = ob_start(function($buffer) {
    if (sspp::inject_login_bar()) {
        // Load the buffer into a DOMDocument object
        $dom = new DOMDocument();

        // Suppress errors due to invalid HTML structures in the buffer
        libxml_use_internal_errors(true);
        $dom->loadHTML($buffer, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();

        // Create a new div element for the login bar
        $loginBarDiv = $dom->createElement('div');
        $loginBarDiv->setAttribute('id', 'sspp-login-bar');
        $loginBarDiv->setAttribute('class', 'sspp-top-logged-in-bar');  // Set the class for styling
        $loginBarDiv->setAttribute('style', 'padding: 5px; padding-left: 20px; text-align: right;');

        // Add some content to the login bar
        $loginBarText = $dom->createTextNode('Logged in as '.sspp::loggedin_user().'.');
        $loginBarDiv->appendChild($loginBarText);

        // Create logout link
        $logoutLink = $dom->createElement('a', 'Logout');
        $logoutLink->setAttribute('href', '?sspp-logout');
        $logoutLink->setAttribute('class', 'sspp-logout-link');
        $logoutLink->setAttribute('style', 'text-decoration: none; color: #ecf0f1; background-color: #e74c3c; padding: 0.5rem 1rem; border-radius: 4px; margin-left: 7px; margin-right: 20px;');

        // Append logout link to the login bar div
        $loginBarDiv->appendChild($logoutLink);

        // Append the login bar div to the body
        $dom->getElementsByTagName('body')->item(0)->appendChild($loginBarDiv);

        // Create and insert style element
        $style = $dom->createElement('style', '
         body:has(.sspp-top-logged-in-bar) {
            margin-top: 50px;
           
         }
         
         
            .sspp-logout-link {
                text-decoration: none;
                color: #ecf0f1;
                background-color: #e74c3c;
                padding: 0.5rem 1rem;
                border-radius: 4px;
                margin-left: 7px;
                margin-right: 20px;
            }
            .sspp-logout-link:hover {
                background-color: #c0392b;
            }
            .sspp-top-logged-in-bar {
                font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
                background-color: #F3FFE1; 
                color: #53973b;
                padding: 1rem;
                padding-left: 3px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                position: fixed;
                width: 100%;
                top: 0;
                z-index: 1000;
                padding-left: 50px;
            }
            .sspp-top-logged-in-bar .welcome {
                font-size: 1.7rem;
                margin-left: 15px;
            }
        ');
        $dom->getElementsByTagName('head')->item(0)->appendChild($style);

        // Return the modified buffer
        $buffer = $dom->saveHTML();
    }
    return $buffer;
});



