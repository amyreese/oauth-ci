<?php

/**
 * Copyright (c) 2010   John Reese
 * Licensed under the MIT license.
 */

/**
 * Simple data store implementation using CodeIgniter models to
 * store and fetch data to the application's current database.
 * Models used by this are stored in the models/ directory.
 */
class OAuthCIDataStore extends OAuthDataStore
{
	public function __construct()
	{
		$this->ci =& get_instance();
	}

	/**
	 * Search the database for an OAuthConsumer object with the
	 * given consumer key, and return the object if found.
	 * @param string Consumer key
	 * @return object OAuthConsumer object, or false if not found
	 */
	public function lookup_consumer($consumer_key)
	{
		$row = $this->ci->oauth_clients->find_by_key($consumer_key);

		if ($row !== NULL)
		{
			return new OAuthConsumer($row->key, $row->secret);
		}
	}

	/**
	 * Search the database for an Token object for the given
	 * consumer key, and return the object if found.
	 * @param string Consumer key
	 * @param string Token type, "access" or "request"
	 * @param string Token key
	 * @return object Token object, or false if not found
	 */
	public function lookup_token($consumer, $token_type, $token_key)
	{
		$row = $this->ci->oauth_server_tokens->find_by_key($token_key);

		if ($row !== NULL)
		{
			return new OAuthToken($row->key, $row->secret);
		}
	}

	/**
	 * Search the database for existing tokens with the given nonce.
	 * @param string Consumer key
	 * @param string Token key
	 * @param string Nonce
	 * @param string Timestamp
	 * @return boolean True if found, false if not found
	 */
	public function lookup_nonce($consumer, $token, $nonce, $timestamp)
	{
		$client_key = $consumer->key;
		$token_key = "";
		if ($token !== NULL)
		{
			$token_key = $token->key;
		}

		return $this->ci->oauth_nonces->
			create_or_find_duplicate($client_key, $token_key, $timestamp, $nonce);
	}

	/**
	 * Generate and store a new request Token object for the
	 * given consumer and callback.
	 * @param object Consumer object
	 * @param string Callback URI
	 * @return object Request token object
	 */
	public function new_request_token($consumer, $callback=NULL)
	{
		$row = array(
			"type" => "request",
			"authorized" => FALSE,
			"timestamp" => time(),
			"ttl" => 1800,
			"client_key" => $consumer->key,
			"callback_uri" => $callback,
		);

		$row = $this->ci->oauth_server_tokens->generate_and_create($row);

		if ($row !== NULL)
		{
			return new OAuthToken($row->key, $row->secret);
		}
	}

	/**
	 * Generate and store a new access Token object for the
	 * given request Token, Consumer, and verifier.  The given
	 * request Token should also be invalidated.
	 * @param object Request token object
	 * @param object Consumer object
	 * @param string Verifier
	 * @return object Access token object
	 */
	public function new_access_token($token, $consumer, $verifier=NULL)
	{
		$old_row = $this->ci->oauth_server_tokens->find_by_key($token->key);

		if ($old_row === NULL)
		{
			return NULL;
		}

		$new_row = array(
			"type" => "access",
			"authorized" => TRUE,
			"timestamp" => time(),
			"ttl" => 0,
			"client_key" => $consumer->key,
		);

		$new_row = $this->ci->oauth_server_tokens->generate_and_create($new_row);
		$this->ci->oauth_server_tokens->delete_by_key($old_row->key);

		if ($new_row !== NULL)
		{
			return new OAuthToken($new_row->key, $new_row->secret);
		}
	}
}

