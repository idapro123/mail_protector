<?php

/* /////////////////////////////////配置区域///////////////////////////////// */
$config = array();

/* Block threshold */
$config["dynamic_password_ttl"] = 0;   //密码有效期（秒），超过这个有效期后保存的密码将失效，0为不过期
$config["dynamic_password_replace_threshold"] = 5;   //允许同时登录的设备数
$config["login_speed_threshold"] = 1800;   
$config["login_limit_threshold"] = 60;
$config["login_forbid_time"] = 3600;   //单IP在1800秒内登录超过60次，即封禁该IP 3600秒
$config["login_limit_on_single_user_threshold"] = 10;
$config["login_forbid_on_single_user_time"] = 900;     //单用户在1800秒内被登录超过10次，即900秒内禁止该用户登录
$config["block_users_list"] = "admin@ceo@chairman@master"; 
$config["block_users_forbid_time"] = 1800;    //当尝试以列表中用户名登录时（以@隔开），封禁该ip接下来1800秒内的任何登录尝试

/* Redis */
$config["redis_host"] = "127.0.0.1";
$config["redis_port"] = 10086;
$config["redis_auth"] = "";

/* Upstream */
$config["smtp_server"] = "192.168.1.100";
$config["smtp_port"] = 25;
$config["pop3_server"] = "192.168.1.100";
$config["pop3_port"] = 110;
$config["imap_server"] = "192.168.1.100";
$config["imap_port"] = 143;
$config["server_domain"] = "bugaosuni.com";

/* LDAP */
$config['ldap_server'] = "ldap.bugaosuni.com";
$config['ldap_port'] = 389;
$config['ldap_basedn'] = "dc=bugaosuni,dc=com";

/* Login With MFA */
$config['login_with_totp'] = false;
$config["2fa_server_api"] = "http://2fa-api.bugaosuni.com/?user={user}&code={code}&key={key}&sign={sign}";
$config['2fa_server_api_key'] = "mail_protector";
$config['2fa_server_api_secret'] = 'wwwwwwwwwwwwwwwwwwwwwwwwwwwwww';
/* ///////////////////////////////配置区域/////////////////////////////// */


















/* ///////////////////////////////////////////////////////////////////////////// */
/* /////////////////////////////////////警告//////////////////////////////////// */
/* /////////////////////////////////以下是代码区域//////////////////////////////// */
/* ////////////////////////请勿在您不明白的情况下编辑该区域的内容////////////////////// */
/* ///////////////////////////////////////////////////////////////////////////// */

$username = str_replace(array("\r", "\n", "\0", "\t", " "), "", $_SERVER['HTTP_AUTH_USER']);
$password = $_SERVER['HTTP_AUTH_PASS'];
$protocol = strtolower($_SERVER['HTTP_AUTH_PROTOCOL']);
$clientip = $_SERVER['HTTP_CLIENT_IP'];
$totpcode = "";

$config["block_users_list"] = explode("@", $config["block_users_list"]);
if (strlen($config['server_domain']) > 0) $username = str_replace("@".$config['server_domain'], "", $username);

/* Init Redis */
$redis = new Redis();
$redis->connect($config['redis_host'], $config['redis_port'], 2); /* timeout = 2 seconds */
if (!empty($config['redis_auth'])) $redis->auth($config['redis_auth']);

/* 检查IP是否位于黑名单内 */
if (is_blackip($clientip))
{
    error("Authenticaltion fail", "536");
}

/* 检查用户是否位于不可登录名单内 */
if (in_array($username, $config['block_users_list']))
{
    block_ip($clientip, $config['block_users_forbid_time']);
    error("Authenticaltion fail", "537");
}


/* 检查用户的相关阈值是否已触达封禁场景 */
$ip_login_count = (int)$redis->get("IP_LOGIN_".$clientip);
$user_login_count = (int)$redis->get("USER_LOGIN_".strtolower($username));
if ($user_login_count >= $config["login_limit_on_single_user_threshold"])
{
    /* 某一IP持续对一个用户进行爆破的时候，封禁用户同时，同样需要封禁这个IP */
    block_ip($clientip, $config['block_users_forbid_time']);
    error("Authenticaltion fail", "530");
}
if ($ip_login_count >= $config["login_limit_threshold"])
{
    block_ip($clientip, $config['block_users_forbid_time']);
    error("Authenticaltion fail", "531");
}


/* 检查用户附带的TOTP令牌是否合法 */
if ($config['login_with_totp'])
{
    //检查这个令牌是否在Redis中被缓存
    $user_token = $redis->get("USER_TOKEN_".$username);
    $isHit = false;
    if (!empty($user_token))
    {
        $user_token = explode("\n", $user_token);
        if (count($user_token) > 1)
        {
            for($i = 1; $i < count($user_token); $i++)
            {
                $_tmp = explode(",", $user_token[$i], 2);
                if ((int)$_tmp[1] > 0 && (int)$_tmp[1] < time()) continue; /* 已过期的动态口令 */
                
                if ($_tmp[0] === sha1($password.md5($password)))
                {
                    $isHit = true;
                    
                    $code_start = strripos($password, "@");
                    $totpcode = substr($password, $code_start + 1, strlen($password) - $code_start);
                    $password = substr($password, 0, $code_start - strlen($password));
                    
                    break;
                }
            }
        }
    }
    
    //如果没有缓存，则校验这个令牌是否合法
    if (!$isHit)
    {
        $code_start = strripos($password, "@");
        if ($code_start === false)
        {
            /* 写回错误记录 */
            $ip_login_count++;
            $user_login_count++;
            ($ip_login_count <= 1) ? $redis->setex("IP_LOGIN_".$clientip, (int)$config['login_speed_threshold'], $ip_login_count) : $redis->set("IP_LOGIN_".$clientip, $ip_login_count);
            ($user_login_count <= 1) ? $redis->setex("USER_LOGIN_".strtolower($username), (int)$config['login_forbid_on_single_user_time'], $user_login_count) : $redis->set("USER_LOGIN_".strtolower($username), $user_login_count);
            
            error("Authenticaltion fail", "538");
        }
        
        $totpcode = substr($password, $code_start + 1, strlen($password) - $code_start);
        $password = substr($password, 0, $code_start - strlen($password));
        
        if (!check_totp_code_by_remote($username, $totpcode, $config['2fa_server_api_key'], $config['2fa_server_api_secret']))
        {
            /* 写回错误记录 */
            $ip_login_count++;
            $user_login_count++;
            ($ip_login_count <= 1) ? $redis->setex("IP_LOGIN_".$clientip, (int)$config['login_speed_threshold'], $ip_login_count) : $redis->set("IP_LOGIN_".$clientip, $ip_login_count);
            ($user_login_count <= 1) ? $redis->setex("USER_LOGIN_".strtolower($username), (int)$config['login_forbid_on_single_user_time'], $user_login_count) : $redis->set("USER_LOGIN_".strtolower($username), $user_login_count);
            
            error("Authenticaltion fail", "538");
        }
    }
}

/* 前往LDAP服务器验证用户身份 */
if (!ldap_login($username, $password))
{
    /* 写回错误记录 */
    $ip_login_count++;
    $user_login_count++;
    ($ip_login_count <= 1) ? $redis->setex("IP_LOGIN_".$clientip, (int)$config['login_speed_threshold'], $ip_login_count) : $redis->set("IP_LOGIN_".$clientip, $ip_login_count);
    ($user_login_count <= 1) ? $redis->setex("USER_LOGIN_".strtolower($username), (int)$config['login_forbid_on_single_user_time'], $user_login_count) : $redis->set("USER_LOGIN_".strtolower($username), $user_login_count);
    
    error("Authenticaltion fail", "539");
}

/* 登录成功，则删除登录计数 */
$redis->delete("IP_LOGIN_".$clientip);
$redis->delete("USER_LOGIN_".strtolower($username));

if (@$isHit == false)
{
    /* 登录成功，写入Token */
    $_tmpToken = (empty($totpcode)) ? sha1($password.md5($password)) : sha1($password."@".$totpcode.md5($password."@".$totpcode));
    $_tmpToken .= ((int)$config['dynamic_password_ttl'] < 1) ? ",0" : ",".(time()+(int)$config['dynamic_password_ttl']); /* 设置动态口令有效期 */
    $user_token = $redis->get("USER_TOKEN_".$username);
    
    /* 使用FIFO法淘汰超出阈值的旧动态令牌 */
    $_index = 0;
    if (!empty($user_token))
    {
        $user_token = explode("\n", $user_token);
        if (count($user_token) > 1) $_index = (int)$user_token[0]; 
    }else{
        $user_token = array($_index);
    }
    $_index++;
    if ($_index > $config['dynamic_password_replace_threshold']) $_index = 1;
    (isset($user_token[$_index])) ? $user_token[$_index] = $_tmpToken : $user_token[] = $_tmpToken;
    $user_token[0] = $_index;
    $user_token = join("\n", $user_token);
    $redis->set("USER_TOKEN_".$username, $user_token);
}

switch ($protocol)
{
    case "smtp":
        header("Auth-Status: OK");
        header("Auth-Server: ". $config['smtp_server']);
        header("Auth-Port: ". $config['smtp_port']);
        header("Auth-Pass: ". $password);
        header("Auth-User: ". $username);
        exit();
        break;
        
    case "imap":
        header("Auth-Status: OK");
        header("Auth-Server: ". $config['imap_server']);
        header("Auth-Port: ". $config['imap_port']);
        header("Auth-Pass: ". $password);
        header("Auth-User: ". $username);
        exit();
        break;
}



/* Function Area */
function ldap_login($user, $pass)
{

    return true;    ///// ONLY FOR DEBUG

    global $config;
    
    if (!function_exists("ldap_connect")) die("libldap NOT found.");
    
    $ad = @ldap_connect("ldap://{$config['ldap_server']}.{$config['server_domain']}:{$config['ldap_port']}") or exit("Can NOT connect Ldap server.");
    ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ad, LDAP_OPT_REFERRALS, 0);
    
    try {
        $is_bind = ldap_bind($ad, "{$user}@{$config['server_domain']}", $pass);
        if (!$is_bind) return false;
    } catch (Exception $e) {
        return false;
    }
    
    $userdn = '';
    $attributes = array('dn');
    $result = @ldap_search($ad, $config['ldap_basedn'], "(samaccountname={$user})", $attributes);
    if ($result === FALSE)
    {
        $userdn = '';
    }else{
        $entries = ldap_get_entries($ad, $result);
        if ($entries['count'] > 0)
        {
            $userdn = $entries[0]['dn'];
        }else{
            $userdn = '';
        }
    }

    ldap_unbind($ad);
    

    return (!empty($userdn));
}

function error($msg="未知错误", $code="403", $wait="3")
{
    header("Auth-Status: ".$msg);
    header("Auth-Error-Code: ".$code);
    header("Auth-Wait: ".$wait);
    exit("");
}

function block_ip($ip, $time=60)
{
    global $redis;
    
    $redis->setex("IP_BLACK_".$ip, (int)$time, "1");
    
    return;
}


function is_blackip($ip)
{
    global $redis;

    $data = $redis->get("IP_BLACK_".$ip);
    return ($data == "1");
}

function check_totp_code_by_remote($user, $code)
{
    global $config;
    
    $key = $config['2fa_server_api_key'];
    $secret = $config['2fa_server_api_secret'];
    $sign = md5($code.$key.$secret.$user);
    
    $url = str_replace(array("{user}", "{code}", "{key}", "{sign}"), array($user, $code, $key, $sign), $config["2fa_server_api"]);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);            //设置访问的url地址
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);           //设置超时
    curl_setopt($ch, CURLOPT_USERAGENT, "_MAIL_PROTECTOR_");   //用户访问代理 User-Agent
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);      //跟踪301
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);        //返回结果
    $r = curl_exec($ch);
    curl_close($ch);
   
    
    return ($r === "ok");
    
}
