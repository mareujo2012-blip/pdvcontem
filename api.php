<?php
session_start();
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__.'/config.php';

define('BRUTE_MAX',5); define('BRUTE_WINDOW',10); define('BRUTE_BLOCK',30);
define('SESSION_TTL',7200); define('ARCHIVE_DAYS',90);
define('BACKUP_DIR',__DIR__.'/backups');

try {
    $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',DB_USER,DB_PASS,
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);
    $pdo->exec("SET time_zone='-03:00'");
} catch(PDOException $e){ http_response_code(500); die(json_encode(['error'=>'Erro de conexao.'])); }

function out($d){echo json_encode($d,JSON_UNESCAPED_UNICODE);exit;}
function err($m,$c=400){http_response_code($c);out(['error'=>$m]);}
function need_auth(){if(empty($_SESSION['role']))err('Nao autenticado',401);}
function is_master(){return($_SESSION['role']??'')==='master';}
function is_dono(){return in_array($_SESSION['role']??'',['dono','master']);}
function gen_id(){return bin2hex(random_bytes(16));}
function get_ip():string{
    foreach(['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $k){
        $v=trim(explode(',',$_SERVER[$k]??'')[0]);
        if(filter_var($v,FILTER_VALIDATE_IP))return $v;
    } return '0.0.0.0';
}
function add_audit(PDO $pdo,string $msg,string $role=''){
    $r=$role?:($_SESSION['role']??'sistema');$ip=get_ip();$u=$_SESSION['name']??'';
    try{$pdo->prepare('INSERT INTO audit_log(msg,role) VALUES(?,?)')->execute(["$msg [IP:$ip".($u?" / $u":"")."]",$r]);}catch(Throwable $e){}
}
function pass_ok(string $p):bool{
    return strlen($p)>=6&&preg_match('/[A-Za-z]/',$p)&&preg_match('/[0-9]/',$p);
}
function days_until_expiry(PDO $pdo,string $role):int{
    $s=$pdo->prepare('SELECT pass_changed_at FROM users WHERE role=?');$s->execute([$role]);$u=$s->fetch();
    if(!$u||!$u['pass_changed_at'])return PASS_EXPIRY_DAYS;
    return PASS_EXPIRY_DAYS-(int)floor((time()-strtotime($u['pass_changed_at']))/86400);
}
function get_csrf():string{
    if(empty($_SESSION['csrf_token']))$_SESSION['csrf_token']=bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}
function validate_csrf():bool{
    if($_SERVER['REQUEST_METHOD']==='GET')return true;
    $sent=$_SERVER['HTTP_X_CSRF_TOKEN']??'';$ok=$_SESSION['csrf_token']??'';
    return !empty($ok)&&!empty($sent)&&hash_equals($ok,$sent);
}
function check_session_timeout():void{
    if(empty($_SESSION['role']))return;
    $last=$_SESSION['last_activity']??0;
    if($last>0&&(time()-$last)>SESSION_TTL){session_unset();session_destroy();http_response_code(401);out(['error'=>'Sessao expirada.','expired'=>true]);}
    $_SESSION['last_activity']=time();
}
function check_blocked(PDO $pdo):array{
    $ip=get_ip();
    $s=$pdo->prepare("SELECT reason,expires_at FROM ip_blocklist WHERE ip_address=? AND (expires_at IS NULL OR expires_at>NOW())");
    $s->execute([$ip]);
    if($b=$s->fetch())return['blocked'=>true,'reason'=>'Acesso bloqueado. '.($b['reason']??''),'retry_after'=>0];
    $win=date('Y-m-d H:i:s',strtotime('-'.BRUTE_WINDOW.' minutes'));
    $s=$pdo->prepare("SELECT COUNT(*) as cnt,MAX(attempted_at) as last FROM login_attempts WHERE ip_address=? AND attempted_at>=?");
    $s->execute([$ip,$win]);$r=$s->fetch();
    if($r['cnt']>=BRUTE_MAX){$unblock=strtotime($r['last'])+(BRUTE_BLOCK*60);$rem=max(0,$unblock-time());if($rem>0)return['blocked'=>true,'reason'=>'Muitas tentativas. Tente em '.ceil($rem/60).' min.','retry_after'=>$rem];$pdo->prepare("DELETE FROM login_attempts WHERE ip_address=? AND attempted_at<?")-> execute([$ip,date('Y-m-d H:i:s',$unblock)]);}
    return['blocked'=>false,'reason'=>'','retry_after'=>0];
}
function record_fail(PDO $pdo,string $action):void{$pdo->prepare('INSERT INTO login_attempts(ip_address,role_tried) VALUES(?,?)')->execute([get_ip(),$action]);}
function clear_attempts(PDO $pdo,string $action):void{$pdo->prepare('DELETE FROM login_attempts WHERE ip_address=? AND role_tried=?')->execute([get_ip(),$action]);}
function check_brute_action(PDO $pdo,string $action,int $max=10,int $window=10):void{
    $ip=get_ip();$win=date('Y-m-d H:i:s',strtotime("-$window minutes"));
    $s=$pdo->prepare("SELECT COUNT(*) as cnt FROM login_attempts WHERE ip_address=? AND role_tried=? AND attempted_at>=?");
    $s->execute([$ip,$action,$win]);$r=$s->fetch();
    if($r['cnt']>=$max)err("Muitas tentativas para '$action'. Aguarde alguns minutos.",429);
}

// ── BACKUP ────────────────────────────────────────────────────
function ensure_backup_dir():void{
    if(!is_dir(BACKUP_DIR)){mkdir(BACKUP_DIR,0750,true);file_put_contents(BACKUP_DIR.'/.htaccess',"Order Allow,Deny\nDeny from all\n");}
}
function do_archive(PDO $pdo,string $cutoff_date,string $origin,string $by,string $notes=''):array{
    ensure_backup_dir();
    $s=$pdo->prepare("SELECT * FROM closings WHERE closed_date < ? ORDER BY closed_date ASC");$s->execute([$cutoff_date]);$rows=$s->fetchAll();
    if(empty($rows))return['ok'=>true,'count'=>0,'message'=>'Nenhum registro para arquivar.'];
    $date_from=$rows[0]['closed_date'];$date_to=end($rows)['closed_date'];
    $backup_id=gen_id();$filename="backup_{$backup_id}.json";$filepath=BACKUP_DIR.'/'.$filename;
    $total_beb=array_sum(array_column($rows,'total_bebida'));$total_com=array_sum(array_column($rows,'total_comida'));
    $total_all=array_sum(array_column($rows,'total_value'));$total_comm=array_sum(array_column($rows,'commission_value'));
    $content=json_encode(['backup_id'=>$backup_id,'origin'=>$origin,'created_at'=>date('c'),'created_by'=>$by,'date_from'=>$date_from,'date_to'=>$date_to,'record_count'=>count($rows),'summary'=>['total_bebida'=>round($total_beb,2),'total_comida'=>round($total_com,2),'total_geral'=>round($total_all,2),'total_comissao'=>round($total_comm,2)],'closings'=>$rows],JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
    if(file_put_contents($filepath,$content)===false)throw new RuntimeException('Nao foi possivel gravar backup.');
    $file_size=filesize($filepath);
    $pdo->prepare("INSERT INTO backups(id,filename,record_count,date_from,date_to,file_size,origin,created_by,notes) VALUES(?,?,?,?,?,?,?,?,?)")->execute([$backup_id,$filename,count($rows),$date_from,$date_to,$file_size,$origin,$by,$notes]);
    $ins=$pdo->prepare("INSERT IGNORE INTO closings_archive(id,backup_id,mesa_id,total_bebida,total_comida,commission_rate,commission_value,total_value,repasse,items,closed_at,closed_date,closed_time) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
    $del=$pdo->prepare("DELETE FROM closings WHERE id=?");
    foreach($rows as $r){$ins->execute([$r['id'],$backup_id,$r['mesa_id'],$r['total_bebida'],$r['total_comida'],$r['commission_rate'],$r['commission_value'],$r['total_value'],$r['repasse'],$r['items'],$r['closed_at']??null,$r['closed_date'],$r['closed_time']]);$del->execute([$r['id']]);}
    return['ok'=>true,'backup_id'=>$backup_id,'filename'=>$filename,'record_count'=>count($rows),'date_from'=>$date_from,'date_to'=>$date_to,'file_size'=>$file_size,'origin'=>$origin];
}

// ── QUERY HELPER: busca em closings + closings_archive (UNION) ──
// Garante que dados arquivados continuam aparecendo nos relatorios
function fetch_closings_range(PDO $pdo,string $start,string $end,array $opts=[]):array{
    $only=$opts['only']??'both'; // 'both','active','archive'
    $rows=[];
    if($only==='active'||$only==='both'){
        $s=$pdo->prepare('SELECT *,"active" as source FROM closings WHERE closed_date>=? AND closed_date<=? ORDER BY closed_date DESC,closed_time DESC');
        $s->execute([$start,$end]);$rows=array_merge($rows,$s->fetchAll());
    }
    if($only==='archive'||$only==='both'){
        $s=$pdo->prepare('SELECT *,"archive" as source FROM closings_archive WHERE closed_date>=? AND closed_date<=? ORDER BY closed_date DESC,closed_time DESC');
        $s->execute([$start,$end]);$rows=array_merge($rows,$s->fetchAll());
    }
    // sort merged by date desc
    usort($rows,function($a,$b){$d=strcmp($b['closed_date'],$a['closed_date']);return $d!==0?$d:strcmp($b['closed_time'],$a['closed_time']);});
    return $rows;
}

$action=trim($_GET['action']??$_POST['action']??'');
$body=json_decode(file_get_contents('php://input'),true);if(!is_array($body))$body=$_POST;
if(!preg_match('/^[a-z_]{1,60}$/',$action))err('Acao invalida',400);

// ── ROTAS PUBLICAS ────────────────────────────────────────────
if($action==='get_csrf_token')out(['csrf_token'=>get_csrf()]);

if($action==='login'){
    $blk=check_blocked($pdo);
    if($blk['blocked']){http_response_code(429);out(['error'=>$blk['reason'],'retry_after'=>$blk['retry_after'],'blocked'=>true]);}
    $role=trim($body['role']??'');$pass=$body['password']??'';
    if(!in_array($role,['dono','parceiro','master']))err('Perfil invalido',400);
    $valid=false;
    $s=$pdo->prepare('SELECT * FROM users WHERE role=?');$s->execute([$role]);$user=$s->fetch();
    if($role==='master' && defined('MASTER_PASSWORD') && $pass===MASTER_PASSWORD){$valid=true;}
    else{$valid=$user&&password_verify($pass,$user['password_hash']);}
    if(!$valid){
        $pdo->prepare('INSERT INTO login_attempts(ip_address,role_tried) VALUES(?,?)')->execute([get_ip(),$role]);
        add_audit($pdo,"Login falhou: $role",'sistema');
        $win=date('Y-m-d H:i:s',strtotime('-'.BRUTE_WINDOW.' minutes'));
        $s2=$pdo->prepare('SELECT COUNT(*) as cnt FROM login_attempts WHERE ip_address=? AND attempted_at>=?');$s2->execute([get_ip(),$win]);$cnt=(int)$s2->fetch()['cnt'];
        $rem=max(0,BRUTE_MAX-$cnt);$msg='Senha incorreta.';
        if($rem<=2&&$rem>0)$msg.=" {$rem} tentativa(s) restante(s).";
        http_response_code(401);out(['error'=>$msg,'remaining_tries'=>$rem]);
    }
    $pdo->prepare('DELETE FROM login_attempts WHERE ip_address=?')->execute([get_ip()]);
    session_regenerate_id(true);
    if($role==='master'){$_SESSION['role']='master';$_SESSION['name']='Master Admin';$_SESSION['theme']='dark';}
    else{$_SESSION['role']=$user['role'];$_SESSION['name']=$user['name'];$_SESSION['theme']=$user['theme']??'dark';}
    $_SESSION['last_activity']=time();$_SESSION['csrf_token']=bin2hex(random_bytes(32));
    $days=($role==='master')?9999:days_until_expiry($pdo,$role);
    add_audit($pdo,'Login realizado',$role);
    out(['ok'=>true,'role'=>$_SESSION['role'],'name'=>$_SESSION['name'],'theme'=>$_SESSION['theme'],'csrf_token'=>$_SESSION['csrf_token'],'days_remaining'=>$days,'pass_expired'=>($days<=0)]);
}

if($action==='logout'){
    if(!empty($_SESSION['role']))add_audit($pdo,'Logout',$_SESSION['role']);
    session_unset();session_destroy();out(['ok'=>true]);
}

if($action==='check_session'){
    if(empty($_SESSION['role']))out(['authenticated'=>false]);
    $last=$_SESSION['last_activity']??0;
    if($last>0&&(time()-$last)>SESSION_TTL){session_unset();session_destroy();out(['authenticated'=>false,'reason'=>'timeout']);}
    $_SESSION['last_activity']=time();
    $role=$_SESSION['role'];$days=($role==='master')?9999:days_until_expiry($pdo,$role);
    $theme='dark';
    if($role!=='master'){$s=$pdo->prepare('SELECT theme FROM users WHERE role=?');$s->execute([$role]);$u=$s->fetch();$theme=$u['theme']??'dark';}
    out(['authenticated'=>true,'role'=>$role,'name'=>$_SESSION['name'],'theme'=>$theme,'csrf_token'=>get_csrf(),'days_remaining'=>$days,'pass_expired'=>($days<=0)]);
}

need_auth();check_session_timeout();
if($_SERVER['REQUEST_METHOD']==='POST'&&!validate_csrf()){add_audit($pdo,"CSRF invalido: $action");err('Token de seguranca invalido. Recarregue a pagina.',403);}

if($action==='save_theme'){
    $t=$body['theme']??'dark';if(!in_array($t,['dark','light']))err('Invalido');
    if($_SESSION['role']!=='master')$pdo->prepare('UPDATE users SET theme=? WHERE role=?')->execute([$t,$_SESSION['role']]);
    $_SESSION['theme']=$t;out(['ok'=>true,'theme'=>$t]);
}

if($action==='init'){
    $products=$pdo->query('SELECT * FROM products WHERE active=1 ORDER BY category,name')->fetchAll();
    $cfg_rows=$pdo->query('SELECT config_key,config_value FROM app_config')->fetchAll();
    $cfg=[];foreach($cfg_rows as $r)$cfg[$r['config_key']]=$r['config_value'];
    $order_rows=$pdo->query("SELECT * FROM orders WHERE status='open' ORDER BY created_at")->fetchAll();
    $by_mesa=[];foreach($order_rows as $o)$by_mesa[$o['mesa_id']][]=$o;
    $role=$_SESSION['role'];$days=($role==='master')?9999:days_until_expiry($pdo,$role);
    $theme='dark';
    if($role!=='master'){$s=$pdo->prepare('SELECT theme FROM users WHERE role=?');$s->execute([$role]);$u=$s->fetch();$theme=$u['theme']??'dark';}
    $cutoff=date('Y-m-d',strtotime('-'.ARCHIVE_DAYS.' days'));
    $sa=$pdo->prepare("SELECT COUNT(*) as cnt FROM closings WHERE closed_date < ?");$sa->execute([$cutoff]);
    $archive_pending=(int)$sa->fetch()['cnt'];
    out(['products'=>$products,'config'=>$cfg,'orders_by_mesa'=>$by_mesa,'theme'=>$theme,'csrf_token'=>get_csrf(),'days_remaining'=>$days,'pass_expired'=>($days<=0),'archive_pending'=>$archive_pending]);
}

// ── PRODUTOS ──────────────────────────────────────────────────
if($action==='get_products')out($pdo->query('SELECT * FROM products WHERE active=1 ORDER BY category,name')->fetchAll());

if($action==='save_product'){
    if(!is_dono())err('Sem permissao',403);
    $name=trim(htmlspecialchars($body['name']??'',ENT_QUOTES,'UTF-8'));$price=round((float)($body['price']??-1),2);$cat=$body['category']??'';$id=$body['id']??null;
    if($name===''||strlen($name)>100)err('Nome invalido');if($price<0||$price>99999.99)err('Preco invalido');if(!in_array($cat,['bebida','comida']))err('Categoria invalida');
    if($id){
        $s=$pdo->prepare('SELECT name,price FROM products WHERE id=? AND active=1');$s->execute([$id]);$old_product=$s->fetch();
        if(!$old_product)err('Produto nao encontrado',404);
        $pdo->prepare('UPDATE products SET name=?,price=?,category=? WHERE id=?')->execute([$name,$price,$cat,$id]);
        $msg = "Produto editado: ID:$id. Antigo: {$old_product['name']} (R$".(float)$old_product['price'].") -> Novo: $name (R$".(float)$price.")";
        add_audit($pdo,$msg);
        out(['ok'=>true,'id'=>$id]);
    } else {
        $nid=gen_id();
        $pdo->prepare('INSERT INTO products(id,name,price,category) VALUES(?,?,?,?)')->execute([$nid,$name,$price,$cat]);
        add_audit($pdo,"Produto adicionado: $name (R$".(float)$price.")");
        out(['ok'=>true,'id'=>$nid]);
    }
}

if($action==='delete_product'){
    if(!is_dono())err('Sem permissao',403);
    $id=$body['id']??'';$s=$pdo->prepare('SELECT name FROM products WHERE id=?');$s->execute([$id]);$p=$s->fetch();
    if($p){$pdo->prepare('UPDATE products SET active=0 WHERE id=?')->execute([$id]);add_audit($pdo,"Produto removido: {$p['name']}");}
    out(['ok'=>true]);
}

// ── PEDIDOS ───────────────────────────────────────────────────
if($action==='get_orders'){$mesa=trim($_GET['mesa']??'');if($mesa==='')err('Mesa invalida');$s=$pdo->prepare("SELECT * FROM orders WHERE mesa_id=? AND status='open' ORDER BY created_at");$s->execute([$mesa]);out($s->fetchAll());}
if($action==='get_all_open_orders'){$rows=$pdo->query("SELECT * FROM orders WHERE status='open' ORDER BY mesa_id,created_at")->fetchAll();$r=[];foreach($rows as $o)$r[$o['mesa_id']][]=$o;out($r);}

if($action==='add_order'){
    $mesa_id=trim($body['mesa_id']??'');$name=trim(htmlspecialchars($body['product_name']??'',ENT_QUOTES,'UTF-8'));$price=round((float)($body['price']??-1),2);$cat=$body['category']??'';
    if($mesa_id===''||$name===''||strlen($name)>100||$price<0||$price>99999)err('Dados invalidos');
    if(!in_array($cat,['bebida','comida']))err('Categoria invalida');
    if($_SESSION['role']==='parceiro'&&$cat!=='comida')err('Parceiro so pode lancar comida',403);
    if($_SESSION['role']==='dono'&&$cat!=='bebida')err('Distribuidora so pode lancar bebida',403);
    $s=$pdo->prepare("SELECT id,qty FROM orders WHERE mesa_id=? AND product_name=? AND category=? AND status='open'");$s->execute([$mesa_id,$name,$cat]);$ex=$s->fetch();
    if($ex){$pdo->prepare('UPDATE orders SET qty=qty+1 WHERE id=?')->execute([$ex['id']]);out(['ok'=>true,'id'=>$ex['id']]);}
    else{$nid=gen_id();$pdo->prepare('INSERT INTO orders(id,mesa_id,product_name,price,category,qty,created_by) VALUES(?,?,?,?,?,1,?)')->execute([$nid,$mesa_id,$name,$price,$cat,$_SESSION['role']]);out(['ok'=>true,'id'=>$nid]);}
}

if($action==='update_order'){
    $id=$body['id']??'';$qty=(int)($body['qty']??0);if(!$id)err('ID obrigatorio');
    $s=$pdo->prepare("SELECT created_by,category,mesa_id FROM orders WHERE id=? AND status='open'");$s->execute([$id]);$order=$s->fetch();
    if(!$order)err('Pedido nao encontrado',404);
    if($_SESSION['role']==='parceiro'&&$order['category']!=='comida')err('Sem permissao',403);
    if($_SESSION['role']==='dono'&&$order['category']!=='bebida')err('Sem permissao',403);
    if($qty<=0)$pdo->prepare('DELETE FROM orders WHERE id=?')->execute([$id]);
    else{if($qty>999)err('Qtd invalida');$pdo->prepare('UPDATE orders SET qty=? WHERE id=?')->execute([$qty,$id]);}
    out(['ok'=>true]);
}

if($action==='cancel_mesa'){
    if(!is_dono())err('Sem permissao',403);$mesa=trim($body['mesa_id']??'');if($mesa==='')err('Mesa invalida');
    $pdo->prepare("DELETE FROM orders WHERE mesa_id=? AND status='open'")->execute([$mesa]);add_audit($pdo,"$mesa: pedidos cancelados");out(['ok'=>true]);
}

if($action==='close_mesa'){
    if(!is_dono())err('Sem permissao',403);
    $mesa_id=trim($body['mesa_id']??'');$comm_rate=round((float)($body['commission_rate']??15),2);
    if($mesa_id==='')err('Mesa invalida');if($comm_rate<0||$comm_rate>100)err('Comissao invalida');
    $s=$pdo->prepare("SELECT * FROM orders WHERE mesa_id=? AND status='open'");$s->execute([$mesa_id]);$orders=$s->fetchAll();
    if(empty($orders))err('Mesa sem pedidos');
    $tB=0;$tC=0;$items=0;
    foreach($orders as $o){$line=round((float)$o['price']*(int)$o['qty'],2);if($o['category']==='bebida')$tB+=$line;else $tC+=$line;$items+=(int)$o['qty'];}
    $cm=round($tC*$comm_rate/100,2);$total=round($tB+$tC,2);$rep=round($tC-$cm,2);
    $now=new DateTime();$nid=gen_id();
    $pdo->prepare('INSERT INTO closings(id,mesa_id,total_bebida,total_comida,commission_rate,commission_value,total_value,repasse,items,closed_date,closed_time) VALUES(?,?,?,?,?,?,?,?,?,?,?)')->execute([$nid,$mesa_id,$tB,$tC,$comm_rate,$cm,$total,$rep,$items,$now->format('Y-m-d'),$now->format('H:i')]);
    $pdo->prepare("DELETE FROM orders WHERE mesa_id=? AND status='open'")->execute([$mesa_id]);
    add_audit($pdo,sprintf('%s fechada — Beb:R$%.2f | Com:R$%.2f | Total:R$%.2f',$mesa_id,$tB,$tC,$total));
    out(['ok'=>true,'tB'=>$tB,'tC'=>$tC,'cm'=>$cm,'total'=>$total,'rep'=>$rep,'items'=>$items]);
}

// ── RELATÓRIO — busca em AMBAS as tabelas ─────────────────────
if($action==='get_report'){
    if(!is_dono())err('Sem permissao',403);
    $start=$_GET['start']??date('Y-m-d');$end=$_GET['end']??date('Y-m-d');
    if(!preg_match('/^\d{4}-\d{2}-\d{2}$/',$start)||!preg_match('/^\d{4}-\d{2}-\d{2}$/',$end))err('Data invalida');
    if($start>$end)[$start,$end]=[$end,$start];
    // UNION closings + closings_archive para que dados arquivados apareçam normalmente
    $rows=fetch_closings_range($pdo,$start,$end);
    out($rows);
}

// ── RELATÓRIO MASTER — com filtros avancados ──────────────────
if($action==='get_master_report'){
    if(!is_master())err('Sem permissao',403);
    $start=$_GET['start']??date('Y-m-d');$end=$_GET['end']??date('Y-m-d');
    $filter=$_GET['filter']??'all'; // all | distribuidora | parceiro | comissao
    if(!preg_match('/^\d{4}-\d{2}-\d{2}$/',$start)||!preg_match('/^\d{4}-\d{2}-\d{2}$/',$end))err('Data invalida');
    if($start>$end)[$start,$end]=[$end,$start];

    $rows=fetch_closings_range($pdo,$start,$end);

    // Calcular resumo por filtro
    $summary=[
        'total_bebida'=>0,'total_comida'=>0,'total_geral'=>0,
        'total_comissao'=>0,'total_repasse'=>0,'mesas'=>0,
        'total_distribuidora'=>0, // bebidas + comissao
    ];
    foreach($rows as $r){
        $beb=(float)$r['total_bebida'];$com=(float)$r['total_comida'];$cmv=(float)$r['commission_value'];
        $summary['total_bebida']+=$beb;
        $summary['total_comida']+=$com;
        $summary['total_geral']+=(float)$r['total_value'];
        $summary['total_comissao']+=$cmv;
        $summary['total_repasse']+=(float)$r['repasse'];
        $summary['total_distribuidora']+=($beb+$cmv);
        $summary['mesas']++;
    }
    foreach($summary as $k=>$v)if(is_float($v))$summary[$k]=round($v,2);

    // Filtrar registros para exibicao conforme filtro
    $filtered=$rows; // sempre retorna tudo; filtro é aplicado no frontend para consistência

    // Agrupar por dia para breakdown
    $by_day=[];
    foreach($rows as $r){
        $d=$r['closed_date'];if(!isset($by_day[$d]))$by_day[$d]=[];$by_day[$d][]=$r;
    }
    krsort($by_day);

    out(['rows'=>$filtered,'summary'=>$summary,'by_day'=>$by_day,'filter'=>$filter,'start'=>$start,'end'=>$end]);
}

// ── CONFIGURAÇÕES ─────────────────────────────────────────────
if($action==='get_config'){$rows=$pdo->query('SELECT config_key,config_value FROM app_config')->fetchAll();$cfg=[];foreach($rows as $r)$cfg[$r['config_key']]=$r['config_value'];out($cfg);}

if($action==='save_config'){
    if(!is_dono())err('Sem permissao',403);
    $allowed=['commission_rate','nome_d','nome_p','num_mesas'];
    $s=$pdo->prepare('INSERT INTO app_config(config_key,config_value) VALUES(?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)');
    foreach($body as $k=>$v)if(in_array($k,$allowed))$s->execute([$k,htmlspecialchars(trim((string)$v),ENT_QUOTES,'UTF-8')]);
    add_audit($pdo,'Configuracoes salvas');out(['ok'=>true]);
}

// ── SENHAS ────────────────────────────────────────────────────
if($action==='change_password'){
    err('Alteração de senha desativada. Apenas o Master Admin pode criar ou mudar senhas.',403);
}

if($action==='master_reset_password'){
    need_auth();if(!is_master())err('Sem permissao',403);
    check_brute_action($pdo,'master_reset',5,15);
    $target=$body['role']??'';$new=$body['new']??'';$confirm=$body['confirm']??'';
    if(!in_array($target,['dono','parceiro','master']))err('Role invalido');
    if($target==='master')err('A senha Master só pode ser alterada diretamente no arquivo config.php por extrema segurança.');
    if(strlen($new)<6)err('Senha curta');if($new!==$confirm)err('Nao coincidem');if(!pass_ok($new))err('Senha fraca');
    $pdo->prepare('UPDATE users SET password_hash=?,pass_changed_at=NOW() WHERE role=?')->execute([password_hash($new,PASSWORD_BCRYPT,['cost'=>12]),$target]);
    add_audit($pdo,"Master redefiniu senha do perfil: $target",'master');
    clear_attempts($pdo,'master_reset');out(['ok'=>true]);
}

if($action==='get_expiry_info'){
    if($_SESSION['role']==='master')out(['dono'=>9999,'parceiro'=>9999]);
    out(['dono'=>days_until_expiry($pdo,'dono'),'parceiro'=>days_until_expiry($pdo,'parceiro')]);
}

// ── SEGURANÇA ─────────────────────────────────────────────────
if($action==='get_security_data'){
    if(!is_master())err('Sem permissao',403);
    $users=$pdo->query("SELECT role,name,pass_changed_at,theme FROM users")->fetchAll();
    $audit=$pdo->query('SELECT * FROM audit_log ORDER BY ts DESC LIMIT 200')->fetchAll();
    $attempts=$pdo->query("SELECT ip_address,role_tried,COUNT(*) as cnt,MAX(attempted_at) as last_attempt FROM login_attempts WHERE attempted_at>=DATE_SUB(NOW(),INTERVAL 1 HOUR) GROUP BY ip_address,role_tried ORDER BY cnt DESC LIMIT 20")->fetchAll();
    $blocklist=$pdo->query("SELECT * FROM ip_blocklist ORDER BY blocked_at DESC LIMIT 20")->fetchAll();
    out(['users'=>$users,'audit'=>$audit,'attempts'=>$attempts,'blocklist'=>$blocklist]);
}
if($action==='block_ip'){
    if(!is_master())err('Sem permissao',403);$ip=trim($body['ip']??'');$reason=trim($body['reason']??'');$hours=(int)($body['hours']??0);
    if(!filter_var($ip,FILTER_VALIDATE_IP))err('IP invalido');
    $expires=$hours>0?date('Y-m-d H:i:s',strtotime("+{$hours} hours")):null;
    $pdo->prepare('INSERT INTO ip_blocklist(ip_address,reason,blocked_by,expires_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE reason=VALUES(reason),expires_at=VALUES(expires_at),blocked_at=NOW()')->execute([$ip,$reason,'master',$expires]);
    add_audit($pdo,"Master bloqueou IP: $ip",'master');out(['ok'=>true]);
}
if($action==='unblock_ip'){
    if(!is_master())err('Sem permissao',403);$ip=trim($body['ip']??'');if(!filter_var($ip,FILTER_VALIDATE_IP))err('IP invalido');
    $pdo->prepare('DELETE FROM ip_blocklist WHERE ip_address=?')->execute([$ip]);
    $pdo->prepare('DELETE FROM login_attempts WHERE ip_address=?')->execute([$ip]);
    add_audit($pdo,"Master desbloqueou IP: $ip",'master');out(['ok'=>true]);
}

// ── BACKUPS ───────────────────────────────────────────────────
if($action==='list_backups'){
    if(!is_master())err('Sem permissao',403);
    $backups=$pdo->query("SELECT * FROM backups ORDER BY created_at DESC")->fetchAll();
    $arch_stats=$pdo->query("SELECT COUNT(*) as total_records, SUM(total_value) as total_valor, MIN(closed_date) as data_inicio, MAX(closed_date) as data_fim FROM closings_archive")->fetch();
    $active_stats=$pdo->query("SELECT COUNT(*) as total_records, SUM(total_value) as total_valor, MIN(closed_date) as data_inicio, MAX(closed_date) as data_fim FROM closings")->fetch();
    $cutoff=date('Y-m-d',strtotime('-'.ARCHIVE_DAYS.' days'));
    $s=$pdo->prepare("SELECT COUNT(*) as cnt, MIN(closed_date) as oldest FROM closings WHERE closed_date < ?");$s->execute([$cutoff]);$pending=$s->fetch();
    out(['backups'=>$backups,'archive_stats'=>$arch_stats,'active_stats'=>$active_stats,'pending'=>$pending,'archive_days'=>ARCHIVE_DAYS]);
}
if($action==='create_backup'){
    if(!is_master())err('Sem permissao',403);
    $mode=$body['mode']??'old';$notes=trim(htmlspecialchars($body['notes']??'',ENT_QUOTES,'UTF-8'));
    if($mode==='all'){
        $latest=date('Y-m-d',strtotime('+1 day'));$s=$pdo->prepare("SELECT COUNT(*) as cnt FROM closings");$s->execute();$cnt=(int)$s->fetch()['cnt'];if($cnt===0)err('Sem fechamentos para arquivar.');$result=do_archive($pdo,$latest,'manual','master',$notes);
    } else {
        $days=(int)$mode; if($days<=0||$days>90)$days=ARCHIVE_DAYS;
        $cutoff=date('Y-m-d',strtotime("-{$days} days"));
        $s=$pdo->prepare("SELECT COUNT(*) as cnt FROM closings WHERE closed_date < ?");$s->execute([$cutoff]);$cnt=(int)$s->fetch()['cnt'];
        if($cnt===0)err("Sem registros com mais de {$days} dia(s) para arquivar.");
        $result=do_archive($pdo,$cutoff,'manual','master',$notes);
    }
    add_audit($pdo,"Backup manual: {$result['record_count']} registros (modo: $mode)",'master');out($result);
}
if($action==='run_auto_archive'){
    if(!is_master())err('Sem permissao',403);
    $cutoff=date('Y-m-d',strtotime('-'.ARCHIVE_DAYS.' days'));
    $s=$pdo->prepare("SELECT COUNT(*) as cnt FROM closings WHERE closed_date < ?");$s->execute([$cutoff]);$cnt=(int)$s->fetch()['cnt'];
    if($cnt===0){out(['ok'=>true,'count'=>0,'message'=>'Nenhum registro a arquivar.']);}
    $result=do_archive($pdo,$cutoff,'automatico','sistema');
    add_audit($pdo,"Arquivo automatico: {$result['record_count']} registros",'master');out($result);
}
if($action==='download_backup'){
    if(!is_master())err('Sem permissao',403);$bid=trim($_GET['id']??'');
    if(!preg_match('/^[a-f0-9]{32}$/',$bid))err('ID invalido');
    $s=$pdo->prepare('SELECT * FROM backups WHERE id=?');$s->execute([$bid]);$bk=$s->fetch();
    if(!$bk)err('Backup nao encontrado',404);$filepath=BACKUP_DIR.'/'.$bk['filename'];
    if(!file_exists($filepath))err('Arquivo nao encontrado no servidor.',404);
    add_audit($pdo,"Download backup: {$bk['filename']}",'master');
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="'.$bk['filename'].'"');
    header('Content-Length: '.filesize($filepath));header('Cache-Control: no-cache');
    readfile($filepath);exit;
}
if($action==='delete_backup'){
    if(!is_master())err('Sem permissao',403);$bid=trim($body['id']??'');$del_arch=(bool)($body['delete_archive']??false);
    if(!preg_match('/^[a-f0-9]{32}$/',$bid))err('ID invalido');
    $s=$pdo->prepare('SELECT * FROM backups WHERE id=?');$s->execute([$bid]);$bk=$s->fetch();if(!$bk)err('Backup nao encontrado',404);
    $filepath=BACKUP_DIR.'/'.$bk['filename'];if(file_exists($filepath))@unlink($filepath);
    if($del_arch){$pdo->prepare('DELETE FROM closings_archive WHERE backup_id=?')->execute([$bid]);add_audit($pdo,"Backup EXCLUIDO com dados: {$bk['filename']}",'master');}
    else add_audit($pdo,"Arquivo de backup excluido (dados mantidos): {$bk['filename']}",'master');
    $pdo->prepare('DELETE FROM backups WHERE id=?')->execute([$bid]);out(['ok'=>true]);
}
if($action==='upload_logo'){
    need_auth();if(!is_dono())err('Sem permissao',403);
    check_brute_action($pdo,'upload_logo',10,30);
    $type=trim($_POST['type']??'');if(!in_array($type,['dono','parceiro']))err('Tipo invalido');
    if(empty($_FILES['image'])||$_FILES['image']['error']){record_fail($pdo,'upload_logo');err('Erro no envio');}
    $file=$_FILES['image'];$ext=strtolower(pathinfo($file['name'],PATHINFO_EXTENSION));
    if(!in_array($ext,['jpg','jpeg','png','webp','gif']))err('Apenas imagens');
    if($file['size']>3*1024*1024)err('Max 3MB');
    $dir=__DIR__.'/uploads';
    if(!is_dir($dir)){mkdir($dir,0755,true);file_put_contents($dir.'/.htaccess',"Options -Indexes\n<FilesMatch \"\.(php|phtml|php3|php4|php5|pl|py|cgi)$\">\nDeny from all\n</FilesMatch>\n");}
    $filename="logo_{$type}.{$ext}";$path=$dir.'/'.$filename;
    foreach(['jpg','jpeg','png','webp','gif'] as $e)@unlink($dir."/logo_{$type}.$e");
    if(!move_uploaded_file($file['tmp_name'],$path))err('Erro ao salvar no servidor');
    $url="uploads/{$filename}?v=".time();
    $pdo->prepare('INSERT INTO app_config(config_key,config_value) VALUES(?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)')->execute(["logo_{$type}",$url]);
    add_audit($pdo,"Logo atualizada: $type",$_SESSION['role']);
    clear_attempts($pdo,'upload_logo');out(['ok'=>true,'url'=>$url]);
}
if($action==='clear_closings'){
    if(!is_master())err('Sem permissao',403);
    $pass=$body['pass']??'';
    if(!defined('MASTER_PASSWORD')||$pass!==MASTER_PASSWORD)err('Senha Master incorreta',403);
    $cnt=$pdo->query('SELECT COUNT(*) as cnt FROM closings')->fetch()['cnt'];
    $pdo->exec('DELETE FROM closings');add_audit($pdo,"Fechamentos ativos excluidos ($cnt registros)",'master');out(['ok'=>true]);
}
if($action==='purge_archive'){
    if(!is_master())err('Sem permissao',403);$all=(bool)($body['all']??false);
    if($all){
        $pass=$body['pass']??'';
        if(!defined('MASTER_PASSWORD')||$pass!==MASTER_PASSWORD)err('Senha Master incorreta',403);
        $cnt=$pdo->query('SELECT COUNT(*) as cnt FROM closings_archive')->fetch()['cnt'];$pdo->exec('DELETE FROM closings_archive');add_audit($pdo,"Todo arquivo historico excluido ($cnt registros)",'master');
    }
    else{$bid=trim($body['id']??'');if(!preg_match('/^[a-f0-9]{32}$/',$bid))err('ID invalido');$cnt=$pdo->prepare('SELECT COUNT(*) as cnt FROM closings_archive WHERE backup_id=?');$cnt->execute([$bid]);$cnt=$cnt->fetch()['cnt'];$pdo->prepare('DELETE FROM closings_archive WHERE backup_id=?')->execute([$bid]);add_audit($pdo,"Dados historicos do backup $bid excluidos ($cnt registros)",'master');}
    out(['ok'=>true]);
}
if($action==='export_data'){
    if(!is_master())err('Sem permissao',403);
    $products=$pdo->query('SELECT * FROM products WHERE active=1')->fetchAll();
    $closings=$pdo->query('SELECT * FROM closings ORDER BY closed_at DESC')->fetchAll();
    $cfg_rows=$pdo->query('SELECT config_key,config_value FROM app_config')->fetchAll();
    $cfg=[];foreach($cfg_rows as $r)$cfg[$r['config_key']]=$r['config_value'];
    $audit=$pdo->query('SELECT * FROM audit_log ORDER BY ts DESC LIMIT 2000')->fetchAll();
    add_audit($pdo,'Exportacao completa de dados','master');
    out(['exported_at'=>date('c'),'products'=>$products,'closings'=>$closings,'config'=>$cfg,'audit_log'=>$audit]);
}

if($action==='seed_data'){
    if(!is_master())err('Sem permissao',403);
    $beb_s=$pdo->query("SELECT * FROM products WHERE active=1 AND category='bebida'")->fetchAll();
    $com_s=$pdo->query("SELECT * FROM products WHERE active=1 AND category='comida'")->fetchAll();
    if(!$beb_s) $beb_s=[['name'=>'Cerveja Teste Seed','price'=>12.90,'category'=>'bebida']];
    if(!$com_s) $com_s=[['name'=>'Porcao Teste Seed','price'=>35.50,'category'=>'comida']];
    for($m=1;$m<=10;$m++){
        $cnt=rand(3,6);
        for($i=0;$i<$cnt;$i++){
            $catv=rand(0,1);
            $p=$catv==0?$beb_s[array_rand($beb_s)]:$com_s[array_rand($com_s)];
            $id=gen_id();
            $pdo->prepare("INSERT INTO orders(id,mesa_id,product_name,price,category,qty,created_by) VALUES(?,?,?,?,?,?,?)")->execute([$id,(string)$m,$p['name'],$p['price'],$p['category'],rand(1,3),'seed']);
        }
    }
    add_audit($pdo,'Massa de dados de teste (Seed) gerada nas mesas 1 a 10.','master');
    out(['ok'=>true]);
}

if($action==='clear_seed'){
    if(!is_master())err('Sem permissao',403);
    $pdo->exec("DELETE FROM orders WHERE created_by='seed'");
    add_audit($pdo,'Massa de dados de teste (Seed) removida.','master');
    out(['ok'=>true]);
}

err("Acao desconhecida.",404);
