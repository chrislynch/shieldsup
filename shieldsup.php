<?php
define('SHIELDS',__DIR__ . '/shields/');
define('SHIELDS_TIMELIMIT',60);
define('SHIELDS_REQLIMIT',30);
define('SHIELDS_BAN',600);
define('SHIELDS_COOKIE',600);
define('SHIELDS_DEBUG',FALSE);
define('SHIELDS_LEARNING',TRUE);
define('SHIELDS_ALERT','support@gravit-e.co.uk');
define('SHIELDS_KEY','1234567891011121314151617181920');

SHIELDS::shield();

class SHIELDS {

  function shield(){
    self::debug('Checking shields...<br>');

    if(!is_writable(SHIELDS)){
      self::errorHTML('Shield directory is not writable. Check your SHIELDS definition and ensure this directory exists and is writable');
      exit();
    }

    if(isset($_GET['SHIELD'])){
      self::debug('Shield bypass received<br>');
      $redirect = self::decrypt($_GET['SHIELD']);
      self::debug('Redirect = ' . $redirect . '<br>');
      if(stripos($redirect,'http://') === 0 || stripos($redirect,'https://') === 0){
        self::debug('Redirect is good<br>');
        setcookie('SHIELD',1,time() + SHIELDS_COOKIE,'/');
        return TRUE;
      } else {
        self::debug('Redirect is a broken link<br>');
      }
    }

    if(@$_COOKIE['SHIELD'] == 1){
      self::debug('Allowing through without checks because we have a cookie');
      return TRUE;
    }

    $file = SHIELDS . ($_SERVER['REMOTE_ADDR']) . '.json';

    if(file_exists($file)){
      $json = file_get_contents($file);
      $sessionobj = json_decode($json);
    } else {
      $sessionobj = new stdClass();
      $sessionobj->blocked = 0;
      $sessionobj->rate = 0;
      $sessionobj->log = array();
    }

    $newlog = new stdClass();
    $newlog->microtime = microtime(TRUE);
    $newlog->datetime = gmdate('Y-m-d H:m:s',$newlog->microtime);
    $newlog->req = $_SERVER['REQUEST_URI'];

    if($sessionobj->blocked > 0){
      $timediff = abs($sessionobj->blocked - microtime(TRUE));
      if($timediff > SHIELDS_BAN){
        self::debug("This IP address was blocked, but is now released<br>");
        $sessionobj->blocked = 0;
        $sessionobj->log = array();
      } else {
        self::debug("This IP address is blocked. " . $timediff . " seconds of " . SHIELDS_BAN . " had elapsed. The timer is now reset<br>");
        $sessionobj->blocked = microtime(TRUE);
      }
    }

    if($sessionobj->blocked == 0){
      if(count($sessionobj->log) > SHIELDS_REQLIMIT){
        $firstlog = $sessionobj->log[0];
        $timediff = abs($firstlog->microtime - $newlog->microtime) ;
        $sessionobj->persec = count($sessionobj->log) / $timediff;
        if($timediff < SHIELDS_TIMELIMIT){
          $sessionobj->blocked = microtime(TRUE);
          file_put_contents(SHIELDS . 'blocked.log',gmdate('Y-m-d H:m:s',$sessionobj->blocked) .
                                  ',blocked,' . $_SERVER['REMOTE_ADDR'] . ',' . self::url() . ',' . $sessionobj->browser . "\n",FILE_APPEND);
          if(strlen(SHIELDS_ALERT) > 0){
            if(SHIELDS_LEARNING){
              mail(SHIELDS_ALERT,'(Learning Mode) Shields Up wants to block ' . $_SERVER['REMOTE_ADDR'],
                "
                Shields UP has detected excess activity from {$_SERVER['REMOTE_ADDR']} on {$_SERVER['HTTP_HOST']}\n\n
                " . print_r($sessionobj,TRUE)
              );
            } else {
              mail(SHIELDS_ALERT,'Shields Up is blocking ' . $_SERVER['REMOTE_ADDR'],
                "
                Shields UP has detected excess activity from {$_SERVER['REMOTE_ADDR']} on {$_SERVER['HTTP_HOST']}\n\n
                " . print_r($sessionobj,TRUE)
              );
            }
          }
          self::debug("IP address is now blocked<br>");
        }
      }
      $sessionobj->log[] = $newlog;
      $sessionobj->log = array_slice($sessionobj->log,(SHIELDS_REQLIMIT + 1) * -1);
    }
    self::debug(count($sessionobj->log) . " requests in " . $timediff . " seconds<br>");

    $sessionobj->browser = $_SERVER['HTTP_USER_AGENT'];
    $agents = file_get_contents(SHIELDS . 'agents.log');
    if(!strstr($agents,$sessionobj->browser)){
      file_put_contents(SHIELDS . 'agents.log', $sessionobj->browser . ',' . gmdate('Y-m-d H:m:s',$newlog->microtime) . ',' . $_SERVER['REMOTE_ADDR'] . "\n",FILE_APPEND);
    }

    // If in learning mode, we always unblock to ensure no blocks are processed.
    if(SHIELDS_LEARNING && $sessionobj->blocked > 0){
      debug("Learning mode is active, so the block will not be applied<br>");
      $sessionobj->blocked = 0;
    }

    $json = json_encode($sessionobj);
    file_put_contents($file,$json);

    if($sessionobj->blocked > 0){
      self::blockHTML();
      exit();
    }

  }

  /*****************************************************************************/

  function debug($message){
    if(SHIELDS_DEBUG){
      print $message;
    }
  }

  function url(){
    $url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
    return $url;
  }

  function blockHTML(){
    header('HTTP/1.0 403 Forbidden');
    $human = random_int(1,12);
    $url = self::url();
    if(strstr($url,'?')){ $redirect = $url; } else { $redirect = $url . '?'; }
    ?>
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <?= self::HTMLhead(); ?>
      <script>
        $(document).ready(function(){
          $('#selectable .ui-state-default').click(function(){
            console.log($(this).data('shield'));
            window.location.replace('<?= $redirect . '&SHIELD=' ?>' + $(this).data('shield'));
          });
        });
      </script>
      <style>
        #selectable .ui-selecting { background: #FECA40; }
        #selectable .ui-selected { background: #F39814; color: white; }
        #selectable { list-style-type: none; margin: 0; padding: 0; padding-left: 10px; width: 100%; }
        #selectable li { margin: 3px; padding: 1px;  float: left; width: 15%; height: 100px; font-size: 4em; text-align: center; }
        #selectable li i { font-size: 80%;}
      .clear { clear: both; }
      </style>
    </head>

    <body>

      <div class="container mt-5">
        <div class="row">
          <div id="lock" class="col-12 col-md-6 offset-md-3">
            <div class="card">
              <div class="card-body text-center">
                <i class="fas fa-shield-virus"></i>
                <h1>
                  Shields Up!
                </h1>
                <p>
                  Your IP address is generating excess traffic to our server.
                </p>
                <p>
                  We have temporarily banned your IP address from accessing our server at this time.
                </p>
                <h3>
                  Not a Robot?
                </h3>
                <p>
                  No problem - just tap on the human being, not the robot, in the grid below.
                </p>
                <ol id="selectable">
                  <?php
                    for($i = 1; $i <= 12; $i++){
                      if($i == $human){
                        $data = self::encrypt($url);
                        print '<li class="ui-state-default" data-shield='. $data .'><i class="fas fa-user-alt"></i></li>';
                      } else {
                        $data = self::encrypt(uniqid() . uniqid());
                        print '<li class="ui-state-default" data-shield='. $data .'><i class="fas fa-robot"></i></li>';
                      }
                    }
                  ?>
                </ol>

                <p class="clear">
                  Your ban will expire at <?= gmdate('G:i.s',strtotime("+" . SHIELDS_BAN . " seconds")) ?>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

    </body>
  </html>
    <?php
  }

  function errorHTML($error){
    header('HTTP/1.0 403 Forbidden');
    ?>
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <?= self::HTMLhead(); ?>
    </head>

    <body>

      <div class="container mt-5">
        <div class="row">
          <div id="lock" class="col-12 col-md-6 offset-md-3">
            <div class="card">
              <div class="card-body text-center">
                <i class="fas fa-exclamation-circle"></i>
                <h1>
                  Shields Down
                </h1>
                <p>
                  <?= $error ?>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

    </body>
  </html>
    <?php
  }

  function HTMLhead(){
    ?>
      <meta charset="UTF-8">

      <!-- Viewport -->
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

      <!-- Bootstrap CSS -->
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">

      <!-- JQuery -->
      <script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=" crossorigin="anonymous"></script>
      <script src="https://code.jquery.com/ui/1.12.1/jquery-ui.min.js" integrity="sha256-VazP97ZCwtekAsvgPBSUwPFKdrwD3unUfSGVYrahUqU=" crossorigin="anonymous"></script>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.theme.min.css" integrity="sha256-AjyoyaRtnGVTywKH/Isxxu5PXI0s4CcE0BzPAX83Ppc=" crossorigin="anonymous" />

      <!-- Popper and Bootstrap JS -->
      <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
      <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>

      <!-- Font Awesome -->
      <script src="https://kit.fontawesome.com/7845385569.js" crossorigin="anonymous"></script>

      <style>
        i {
          font-size: 20vw;
          margin-bottom: 8px;
          color: darkred;
        }
        .card {
          border-color: darkred;
        }
      </style>
    <?php
  }

  static function encrypt($object){
  		$cipher_method = 'aes-128-ctr';
    	$enc_key = openssl_digest(SHIELDS_KEY, 'SHA256', TRUE);
    	$enc_iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher_method));
  		$object = serialize($object);
    	$crypted_token = openssl_encrypt($object, $cipher_method, $enc_key, 0, $enc_iv) . "::" . bin2hex($enc_iv);
    	$crypted_token = base64_encode($crypted_token);
  		unset($token, $cipher_method, $enc_key, $enc_iv);
  		return $crypted_token;
  	}

  	static function decrypt($token){
  		$token = base64_decode($token);
  		list($token, $enc_iv) = explode("::", $token);;
  		$cipher_method = 'aes-128-ctr';
  		$enc_key = openssl_digest(SHIELDS_KEY, 'SHA256', TRUE);
  		$token = openssl_decrypt($token, $cipher_method, $enc_key, 0, hex2bin($enc_iv));
  		unset($cipher_method, $enc_key, $enc_iv);

  		$object = unserialize($token);
  		unset($token);

  		return $object;

  	}


}

?>
