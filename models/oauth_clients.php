<?php

/**
 * Copyright (c) 2010   John Reese
 * Licensed under the MIT license.
 */

/**
 * Model for tracking OAuth client objects.
 *
 * See DATAMODEL or _create_schema() for the database
 * schema assumed by this model.
 */
class Oauth_clients extends Model {
	public function __construct()
	{
		parent::__construct();
		$this->table = "oauth_clients";

		if (element("create_tables", Oauth::$params) == TRUE &&
			!$this->db->table_exists($this->table))
		{
			$this->_create_table();
		}
	}

	/**
	 * Retrieve a client row with the given key.
	 * @param string Client key
	 * @return object Client object
	 */
	public function find_by_key($client_key)
	{
		$query = $this->db->
			where("key", $client_key)->
			get($this->table);

		foreach($query->result() as $row)
		{
			return $row;
		}
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
					`name`  varchar(50) not null,
					`uri`  varchar(200) not null,
					`callback_uri`  varchar(200),
					`user_id`  int(10) unsigned,

					PRIMARY KEY (`id`),
					UNIQUE KEY (`key`),
					KEY (`user_id`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1";
				break;
		}

		$this->db->query($query);
	}
}

