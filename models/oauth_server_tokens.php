<?php

/**
 * Copyright (c) 2010   John Reese
 * Licensed under the MIT license.
 */

/**
 * Model for tracking server token objects.
 *
 * See DATAMODEL or _create_schema() for the database
 * schema assumed by this model.
 */
class Oauth_server_tokens extends Model {
	public function __construct()
	{
		parent::__construct();
		$this->table = "oauth_server_tokens";

		if (element("create_tables", Oauth::$params) == TRUE &&
			!$this->db->table_exists($this->table))
		{
			$this->_create_table();
		}
	}

	/**
	 * Check to see if a key is already in use.
	 * @param string Token key
	 * @return boolean True if exists, false otherwise
	 */
	public function key_exists($token_key)
	{
		$count = $this->db->
			from($this->table)->
			where("key", $token_key)->
			count_all_results();

		return $count > 0;
	}

	/**
	 * Retrieve a token row with the given key.
	 * @param string Token key
	 * @return object Token object, or null if not found
	 */
	public function find_by_key($token_key)
	{
		$query = $this->db->
			where("key", $token_key)->
			get($this->table);

		foreach($query->result() as $row)
		{
			return $row;
		}
	}

	/**
	 * Generate a new key and secret pair, and create
	 * a new token row with the given field values, and
	 * return the new token object.
	 * @param array Token field values
	 * @return object Token object
	 */
	public function generate_and_create($row)
	{
		do
		{
			list($key, $secret) = $this->oauth->generate_key_secret_pair();
		}
		while ($this->key_exists($key));

		$row["key"] = $key;
		$row["secret"] = $secret;

		$this->create($row);

		return $this->find_by_key($key);
	}

	/**
	 * Create a new token row given a set of field values.
	 * @param array Token field values
	 * @return int Token ID
	 */
	public function create($row)
	{
		$this->db->insert($this->table, $row);
		return $this->db->insert_id();
	}

	/**
	 * Delete a token row with the given key.
	 * @param string Token key
	 */
	public function delete_by_key($token_key)
	{
		$this->db->
			where("key", $token_key)->
			delete($this->table);
	}

	/**
	 * Create the table schema.
	 */
	private function _create_table()
	{
		$table = $this->db->dbprefix($this->table);

		switch ($this->db->platform())
		{
			case "mysql":
			case "mysqli":
				$query = "CREATE TABLE `$table` (
					`id`  int(10) unsigned not null auto_increment,
					`key`  varchar(20) not null,
					`secret`  varchar(100) not null,
					`verifier`  varchar(20),
					`type`  enum('request','access') not null default 'request',
					`authorized`  tinyint(3) unsigned not null default '0',
					`timestamp`  int(10) unsigned not null,
					`ttl`  int(10) unsigned not null,
					`callback_uri`  varchar(200),
					`client_key`  varchar(20) not null,
					`user_id`  int(10) unsigned,

					PRIMARY KEY (`id`),
					UNIQUE KEY (`key`),
					KEY (`timestamp`),
					KEY (`ttl`),
					KEY (`user_id`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1";
				break;
		}

		$this->db->query($query);
	}
}


