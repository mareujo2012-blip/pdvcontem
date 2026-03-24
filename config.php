<?php
// ============================================================
// config.php — Configurações do BarPDV
// EDITE ESTE ARQUIVO com os dados do seu banco de dados
// NÃO compartilhe este arquivo publicamente
// ============================================================

// --- Credenciais do Banco de Dados (MySQL) ---
// Encontre esses dados no painel DirectAdmin → MySQL Management
define('DB_HOST', 'localhost');           // Geralmente localhost
define('DB_NAME', 'prod9474_bardpdv');     // Nome do banco criado no DirectAdmin
define('DB_USER', 'prod9474_bardpdv');     // Usuário do banco
define('DB_PASS', 'ZAQ!xsw2CDE#vfr4');   // Senha do banco — ALTERE ISSO

// --- Senha Master (NUNCA armazenada no banco, NUNCA alterável via app) ---
// Esta é a chave de emergência. Guarde em local seguro.
// Para alterar: edite diretamente este arquivo via FTP/FileManager
define('MASTER_PASSWORD', '90860Placa8010!@#$%');

// --- Política de senhas ---
define('PASS_EXPIRY_DAYS', 90);   // Senha expira após 90 dias (3 meses)
define('PASS_WARN_DAYS',   14);   // Aviso 14 dias antes de expirar

// --- Fuso horário ---
date_default_timezone_set('America/Sao_Paulo');

// --- Segurança da sessão ---
ini_set('session.cookie_httponly', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');
