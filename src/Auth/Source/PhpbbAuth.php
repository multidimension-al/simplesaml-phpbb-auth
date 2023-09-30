<?php
namespace SimpleSAML\Module\phpbbauth\Auth\Source;

use PDO;
use PDOException;
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use Exception;

class PhpbbAuth extends \SimpleSAML\Module\core\Auth\UserPassBase
{
    private $phpbb_path;
    private $phpbb_config;
    private $phpbb_passwords_manager;
    private $phpbb_passwords_driver_helper;
    private $phpbb_passwords_drivers;
  	private $phpbb_dbms;
  	private $phpbb_dbhost;
  	private $phpbb_dbport;
  	private $phpbb_dbname;
  	private $phpbb_dbuser;
  	private $phpbb_dbpasswd;
  	private $phpbb_table_prefix;

    public function __construct($info, $config)
    {
        parent::__construct($info, $config);

        if (!is_string($config["phpbb_path"]) || empty($config["phpbb_path"])) {
            throw new Exception("Missing phpBB path in config.");
        }
		
  		$this->phpbb_path = $config["phpbb_path"];
		
  		if (!is_string($config["phpbb_dbms"]) || empty($config["phpbb_dbms"])) {
            throw new Exception("Missing phpBB database type in config.");
        }
		
	  	if (!is_string($config["phpbb_dbhost"]) || empty($config["phpbb_dbhost"])) {
            throw new Exception("Missing phpBB database host in config.");
        }
		
	  	/*if (!is_string($config["phpbb_dbport"]) || empty($config["phpbb_dbport"])) {
            throw new Exception("Missing phpBB database port in config.");
        }*/
		
	  	if (!is_string($config["phpbb_dbname"]) || empty($config["phpbb_dbname"])) {
            throw new Exception("Missing phpBB database name in config.");
        }
	
	  	if (!is_string($config["phpbb_dbuser"]) || empty($config["phpbb_dbuser"])) {
            throw new Exception("Missing phpBB database user in config.");
        }
		
  		if (!is_string($config["phpbb_dbpasswd"]) || empty($config["phpbb_dbpasswd"])) {
            throw new Exception("Missing phpBB database password in config.");
        }
		
	  	if (!is_string($config["phpbb_table_prefix"])) {
            throw new Exception("Missing phpBB database table prefix in config.");
        }
		
		//require_once $this->phpbb_path . "config.php";
		
  		$this->phpbb_dbms = $config["phpbb_dbms"];
  		$this->phpbb_dbhost = $config["phpbb_dbhost"];
  		$this->phpbb_dbport = $config["phpbb_dbport"];
  		$this->phpbb_dbname = $config["phpbb_dbname"];
  		$this->phpbb_dbuser = $config["phpbb_dbuser"];
  		$this->phpbb_dbpasswd = $config["phpbb_dbpasswd"];
  		$this->phpbb_table_prefix = $config["phpbb_table_prefix"];
				
  		//We are using PDO here, so mysqli can just be mysql.
  		if($this->phpbb_dbms == 'mysqli') $this->phpbb_dbms = 'mysql';
  		
          require_once $this->phpbb_path . "phpbb/config/config.php";
          require_once $this->phpbb_path . "phpbb/passwords/manager.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/helper.php";
          require_once $this->phpbb_path . "phpbb/passwords/helper.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/driver_interface.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/rehashable_driver_interface.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/base.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/base_native.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/argon2i.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/argon2id.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/bcrypt.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/bcrypt_2y.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/bcrypt_wcf2.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/convert_password.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/driver_interface.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/helper.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/md5_mybb.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/md5_phpbb2.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/md5_vb.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/salted_md5.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/phpass.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/sha1.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/sha1_smf.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/sha1_wcf1.php";
          require_once $this->phpbb_path . "phpbb/passwords/driver/sha_xf1.php";
  
          $this->phpbb_config = new \phpbb\config\config([]);
          $this->phpbb_passwords_helper = new \phpbb\passwords\helper($this->phpbb_config);
          $this->phpbb_passwords_driver_helper = new \phpbb\passwords\driver\helper($this->phpbb_config);
          $this->phpbb_passwords_drivers = [
              "passwords.driver.bcrypt_2y" => new \phpbb\passwords\driver\bcrypt_2y($this->phpbb_config, $this->phpbb_passwords_driver_helper, 10),
              "passwords.driver.bcrypt" => new \phpbb\passwords\driver\bcrypt($this->phpbb_config, $this->phpbb_passwords_driver_helper, 10),
              "passwords.driver.salted_md5" => new \phpbb\passwords\driver\salted_md5($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.phpass" => new \phpbb\passwords\driver\phpass($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.convert_password" => new \phpbb\passwords\driver\convert_password($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.sha1_smf" => new \phpbb\passwords\driver\sha1_smf($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.sha1" => new \phpbb\passwords\driver\sha1($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.sha1_wcf1" => new \phpbb\passwords\driver\sha1_wcf1($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.md5_mybb" => new \phpbb\passwords\driver\md5_mybb($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.md5_vb" => new \phpbb\passwords\driver\md5_vb($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.sha_xf1" => new \phpbb\passwords\driver\sha_xf1($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.argon2i" => new \phpbb\passwords\driver\argon2i($this->phpbb_config, $this->phpbb_passwords_driver_helper),
              "passwords.driver.argon2id" => new \phpbb\passwords\driver\argon2id($this->phpbb_config, $this->phpbb_passwords_driver_helper),
          ];
  
          $this->phpbb_passwords_manager = new \phpbb\passwords\manager($this->phpbb_config, $this->phpbb_passwords_drivers, $this->phpbb_passwords_helper, array_keys($this->phpbb_passwords_drivers));
						
    }

    protected function login(string $username, string $password): array
    {

		$db = new PDO($this->phpbb_dbms.':host='.$this->phpbb_dbhost.';dbname='.$this->phpbb_dbname, $this->phpbb_dbuser, $this->phpbb_dbpasswd);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->exec("SET NAMES 'utf8'");
        $st = $db->prepare('SELECT user_id, username, user_password, user_email, user_type FROM :table_name WHERE username=:username');
		
		if (!$st->execute(['table_name' => $this->phpbb_table_prefix.'users', 'username' => $username])) {
            throw new Exception('Failed to query database for user.');
        }

        /* Retrieve the row from the database. */
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            /* User not found. */
            SimpleSAML\Logger::warning('PhpbbAuth: Could not find user ' . var_export($username, true) . '.');
            throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
        }

        /* Check the password. */
        if (!$this->phpbb_passwords_manager->check($password, $row['user_password'])) {
            /* Invalid password. */
            SimpleSAML\Logger::warning('PhpbbAuth: Wrong password for user ' . var_export($username, true) . '.');
            throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
        }
		
  		switch($row['user_type']){
  			case 0:
  				$user_type = 'USER_NORMAL';
  			break;
  			case 1:
  				$user_type = 'USER_INACTIVE';
  			break;
  			case 2:
  				$user_type = 'USER_IGNORE';
  			break;
  			case 3:
  				$user_type = 'USER_FOUNDER';
  			break;
  		}

        /* Create the attribute array of the user. */
        $attributes = [
            'user_id' => [$row['user_id']],
			      'uid' => [$username],
            'mail' => [$row['user_email']],
			      'user_type' => [$user_type]
        ];

        /* Return the attributes. */
        return $attributes;

    }
}
