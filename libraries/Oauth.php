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

	/**
	 * Initialize's the OAuth wrapper library.
	 * Called by CI's load->library() module.
	 *
	 * Accepted parameters:
	 *
	 *   server =>
	 *     boolean, true for use as a server
	 *
	 *   datastore =>
	 *     if using a server, optionally specify the name of
	 *     a class extending OAuthDataStore
	 *
	 * @param array Parameters (optional)
	 */
	public function __construct($params=array())
	{
		$this->ci =& get_instance();
		$this->ci->load->helper("array");

		$this->hmac_sha1 = new OAuthSignatureMethod_HMAC_SHA1();
		$this->plaintext = new OAuthSignatureMethod_PLAINTEXT();

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

