<?php

/**
 * Copyright (c) 2010   John Reese
 * Licensed under the MIT license.
 */

require_once("OAuthCI/OAuth.php");

/**
 * OAuth abstraction library for CodeIgniter projects.
 */
class Oauth {
	private $ci = null;

	public static $params = array();

	/**
	 * Initialize's the OAuth wrapper library.
	 * Called by CI's load->library() module.
	 *
	 * Accepted parameters:
	 *
	 *   createtables =>
	 *     automatically create tables for database models
	 *
	 *   datastore =>
	 *     if using a server, optionally specify the name of
	 *     a class extending OAuthDataStore
	 *
	 *   server =>
	 *     boolean, true for use as a server
	 *
	 *   urandom =>
	 *     if using a Unix-ish server with /dev/urandom, use
	 *     /dev/urandom instead of OpenSSL for random bytes
	 *
	 * @param array Parameters (optional)
	 */
	public function __construct($params=array())
	{
		$this->ci =& get_instance();
		$this->ci->load->helper("array");

		$this->params = $params;

		$this->hmac_sha1 = new OAuthSignatureMethod_HMAC_SHA1();
		$this->plaintext = new OAuthSignatureMethod_PLAINTEXT();

		$this->ci->load->model("user");

		# Optionally set up a server object
		if (element("server", $params) == TRUE)
		{
			$this->_init_server($params);
		}
	}

	/**
	 * Process HTTP request data for a temporary token,
	 * and return the token to the consumer if valid.
	 */
	public function serve_request_token()
	{
		try
		{
			$request = OAuthRequest::from_request();
			$token = $this->server->fetch_request_token($request);
			echo $token;
		}
		catch (OAuthException $e)
		{
			show_error($e->getMessage(), 401);
		}
	}

	/**
	 * Process HTTP request data for an OAuth access token,
	 * and return the token data to the consumer if valid.
	 */
	public function serve_access_token()
	{
		try
		{
			$request = OAuthRequest::from_request();
			$token = $this->server->fetch_access_token($request);
			echo $token;
		}
		catch (OAuthException $e)
		{
			show_error($e->getMessage(), 401);
		}
	}

	/**
	 * Validate the HTTP request data for a consumer using
	 * an access token.  If the request is signed and valid,
	 * returns true; otherwise shows error and returns false.
	 * @return boolean Request valid (true), or invalid (false)
	 */
	public function verify_request()
	{
		try
		{
			$request = OAuthRequest::from_request();
			list($consumer, $token) = $this->server->verify_request($request);

			return true;
		}
		catch (OAuthException $e)
		{
			show_error($e->getMessage(), 401);
			return false;
		}
	}

	/**
	 * Generate a key/secret pair for a client or token object.
	 * @return array Key/secret list
	 */
	public function generate_key_secret_pair()
	{
		$key = $this->generate_random_string(12);
		$secret = $this->generate_random_string(72);

		return array($key, $secret);
	}

	/**
	 * Generate a strongly random string with a given number
	 * of bytes, using a secure PRNG source.
	 * @param int Number of base64-encoded bytes
	 * @return string Random string
	 */
	private function generate_random_bytes($bytes)
	{
		$bytes = (int) $bytes;
		if ($bytes < 1)
			$bytes = 1;

		if (element("urandom", $this->params) == TRUE)
		{
			$urandom = fopen("/dev/urandom", "rb");
			$data = fread($urandom, $bytes);
			fclose($urandom);

			return $data;
		}
		elseif (function_exists("openssl_random_pseudo_bytes"))
		{
			return openssl_random_pseudo_bytes($bytes);
		}
		else
		{
			return shell_exec("openssl rand $bytes");
		}
	}

	/**
	 * Generate a strongly random, URI-safe, base64-encoded
	 * string with a given number of encoded bytes.
	 * @param int Number of base64-encoded bytes
	 * @return string Random string
	 */
	private function generate_random_string($bytes)
	{
		$data = $this->generate_random_bytes($bytes);
		return strtr(base64_encode($data), "+/", "-_");
	}

	/**
	 * Initialize an OAuthServer object with an appropriate
	 * OAuthDataStore object.
	 * @params array Parameters
	 */
	private function _init_server($params)
	{
		# Allow custom datastore objects to be used
		$datastore = element("datastore", $params);
		if (is_string($datastore) && class_exists($datastore)
			&& is_subclass_of($datastore, "OAuthDataStore"))
		{
			$datastore = new $datastore();
		}
		elseif ($datastore === "OAuthCIDataStore")
		{
			require_once("OAuthCI/OAuthCIDataStore.php");
			$datastore = new OAuthCIDataStore();

			# Load models used by the data store
			$this->ci->load->model("oauth_clients");
			$this->ci->load->model("oauth_server_tokens");
			$this->ci->load->model("oauth_nonces");
		}
		else
		{
			require_once("OAuthCI/OAuthFakeDataStore.php");
			$datastore = new OAuthFakeDataStore();
		}

		# Initialize the server and signature methods
		$this->server = new OAuthServer($datastore);
		$this->server->add_signature_method($this->hmac_sha1);
		$this->server->add_signature_method($this->plaintext);
	}
}

