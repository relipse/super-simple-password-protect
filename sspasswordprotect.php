<?php
/**
 * The goal of this file is to password protect other files by a
 * simple 
 * @example require('sspasswordprotect.php'); 
 * If not logged in, it will attempt
 */
class sspp {
	private static $users = array('admin'=>'admin84');

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
	     	 header('Location: '.basename(__FILE__).'?login&goto='.urlencode($_SERVER['REQUEST_URI']));
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

	public static function html_loggedin_bar(){
       ?><div class="divSSPPLoggedInBar">Logged in as <span class="loggedin_user"><?=self::loggedin_user()?>.</span> <a class="logout" href="<?php 
           echo basename(__FILE__).'?logout&goto='.urlencode($_SERVER['PHP_SELF']);
       ?>">Log out</a></div><?php
	}

	public static function page_protect_with_login(){
		$gotoquery = isset($_GET['goto'])?'?goto='.urlencode($_GET['goto']) : '';
		?>
		<!doctype html>
		<html>
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
		.frmSSPPLogin label {
			display: block;
		}
		.frmSSPPLogin label input{
			margin-left: .5em;
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
			<label>Username<input type="text" name="user"></label>
			<label>Password<input type="password" name="pw"></label>
			<button type="submit">Login</button>
		</form>
		</body>
		</html><?php
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


