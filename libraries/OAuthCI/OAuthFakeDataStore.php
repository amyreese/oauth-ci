<?php

/**
 * Copyright (c) 2010   John Reese
 * Licensed under the MIT license.
 */

/**
 * Generic data store implementation that just generates static
 * consumer and token objects, and maintains no persistent storage.
 * This is only useful in testing basic OAuth functionality, and
 * should not be used in a production system.
 */
class OAuthFakeDataStore extends OAuthDataStore
{
	/**
	 * Search the database for an OAuthConsumer object with the
	 * given consumer key, and return the object if found.
	 * @param string Consumer key
	 * @return object OAuthConsumer object, or false if not found
	 */
	function lookup_consumer($consumer_key) {
		return new OAuthConsumer($consumer_key, "secret");
	}

	/**
	 * Search the database for an Token object for the given
	 * consumer key, and return the object if found.
	 * @param string Consumer key
	 * @param string Token type, "access" or "request"
	 * @param string Token key
	 * @return object Token object, or false if not found
	 */
	function lookup_token($consumer, $token_type, $token) {
		return new OAuthToken($token, "secret");
	}

	/**
	 * Search the database for existing tokens with the given nonce.
	 * @param string Consumer key
	 * @param string Token key
	 * @param string Nonce
	 * @param string Timestamp
	 * @return boolean True if found, false if not found
	 */
	function lookup_nonce($consumer, $token, $nonce, $timestamp) {
		return false;
	}

	/**
	 * Generate and store a new request Token object for the
	 * given consumer and callback.
	 * @param object Consumer object
	 * @param string Callback URI
	 * @return object Request token object
	 */
	function new_request_token($consumer, $callback = null) {
		return new OAuthToken("request_key", "secret");
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
	function new_access_token($token, $consumer, $verifier = null) {
		return new OAuthToken("access_key", "secret");
	}
}
