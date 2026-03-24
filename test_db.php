<?php
/**
 * test_db.php — Script de Diagnóstico para BarPDV
 * Suba este arquivo para a pasta do seu aplicativo no servidor e acesse via navegador.
 */

require_once 'config.php';

header('Content-Type: text/plain; charset=utf-8');

echo "--- Diagnóstico de Conexão BarPDV ---\n\n";

echo "1. Verificando Extensões PHP:\n";
echo "PDO: " . (extension_loaded('pdo') ? "OK" : "ERRO (Faltando)") . "\n";
echo "PDO MySQL: " . (extension_loaded('pdo_mysql') ? "OK" : "ERRO (Faltando)") . "\n\n";

echo "2. Testando Conexão com o Banco:\n";
try {
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 5
    ]);
    echo "Conexão: SUCESSO ✓\n\n";
    
    echo "3. Verificando Tabelas Necessárias:\n";
    $tables = ['users', 'products', 'orders', 'app_config', 'closings', 'audit_log'];
    foreach ($tables as $t) {
        $stmt = $pdo->query("SHOW TABLES LIKE '$t'");
        if ($stmt->fetch()) {
            echo "Tabela '$t': OK ✓\n";
        } else {
            echo "Tabela '$t': NÃO ENCONTRADA ❌ (Importe o schema.sql!)\n";
        }
    }
    
} catch (PDOException $e) {
    echo "Erro na Conexão: " . $e->getMessage() . "\n";
    echo "\nVerifique se os dados no config.php estão corretos:\n";
    echo "Host: " . DB_HOST . "\n";
    echo "Banco: " . DB_NAME . "\n";
    echo "Usuário: " . DB_USER . "\n";
}

echo "\n--- Fim do Diagnóstico ---";
