# SimpleSAMLphp Module: phpBB Auth
This is a module for SimpleSAMLphp that will allow you to use your phpBB forum as an authentication source.


## Configuration

Update your `config.php` file to make sure the module is enabled.

````
    'module.enable' => [
        'phpbbauth' => true,
         ....
     ];
````

Update your `authsources.php` file to add variables specific to your phpBB installation:

````
    'phpbb' => [
        'phpbbauth:PhpbbAuth',
        'phpbb_path' => '/path/to/your/forum/',
        'phpbb_dbms' => 'mysql', //Use mysql instead of mysqli
        'phpbb_dbhost' => 'localhost',
        'phpbb_dbport' => '',
        'phpbb_dbname' => 'YOUR DB NAME',
        'phpbb_dbuser' => 'YOUR DB USERNAME',
        'phpbb_dbpasswd' => 'YOUR DB PASSWORD',
        'phpbb_table_prefix' => 'phpbb3_',
    ],
````
