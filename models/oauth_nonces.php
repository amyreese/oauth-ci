<?php

/**
 * Copyright (c) 2010   John Reese
 * Licensed under the MIT license.
 */

/**
 * Model for tracking OAuth nonce objects.
 *
 * See DATAMODEL or _create_schema() for the database
 * schema assumed by this model.
 */
class Oauth_nonces extends Model {
	public function __construct()
	{
		parent::__construct();
		$this->table = "oauth_nonces";

		if (element("create_tables", Oauth::$params) == TRUE &&
			!$this->db->table_exists($this->table))
		{
			$this->_create_table();
		}
	}


	/**
	 * Given a client key, token key, timestamp, and nonce,
	 * find any existing matches in the database.  If found,
	 * return immediately, otherwise insert the given data.
	 * @param string Client key
	 * @param string Token key
	 * @param int Timestamp
	 * @param string Nonce
	 * @return boolean True if data was found, false if inserted
	 */
	public function create_or_find_duplicate($client_key, $token_key, $timestamp, $nonce)
	{
		$row = array(
			"client_key" => $client_key,
			"token_key" => $token_key,
			"timestamp" => $timestamp,
			"nonce" => $nonce,
		);

		$count = $this->db->
			from($this->table)->
			where($row)->
			count_all_results();

		if ($count > 0)
		{
			return TRUE;
		}

		$this->db->insert($this->table, $row);

		return FALSE;
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
					`client_key`  varchar(20) not null,
					`token_key`  varchar(20) not null,
					`timestamp`  int(10) unsigned,
					`nonce`  varchar(100) not null,

					PRIMARY KEY (`client_key`, `token_key`, `timestamp`, `nonce`),
					KEY (`timestamp`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1";
				break;
		}

		$this->db->query($query);
	}
}


