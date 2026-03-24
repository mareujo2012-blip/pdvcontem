-- 
-- Esquema de Banco de Dados — BarPDV (Contem Distribuidora)
-- Importe este arquivo no phpMyAdmin do seu DirectAdmin
--

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "-03:00";

-- 1. Tabela de Configurações
CREATE TABLE IF NOT EXISTS `app_config` (
  `config_key` varchar(50) NOT NULL,
  `config_value` text DEFAULT NULL,
  PRIMARY KEY (`config_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Configurações iniciais
INSERT IGNORE INTO `app_config` (`config_key`, `config_value`) VALUES
('commission_rate', '15'),
('nome_d', 'Contem Distribuidora'),
('nome_p', 'Parceiro'),
('num_mesas', '20');

-- 2. Tabela de Auditoria
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `msg` text NOT NULL,
  `role` varchar(20) DEFAULT 'sistema',
  `ts` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_ts` (`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Tabela de Backups
CREATE TABLE IF NOT EXISTS `backups` (
  `id` char(32) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `record_count` int(11) DEFAULT 0,
  `date_from` date DEFAULT NULL,
  `date_to` date DEFAULT NULL,
  `file_size` int(11) DEFAULT 0,
  `origin` varchar(50) DEFAULT 'manual',
  `created_by` varchar(50) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Tabela de Fechamentos Ativos
CREATE TABLE IF NOT EXISTS `closings` (
  `id` char(32) NOT NULL,
  `mesa_id` varchar(20) NOT NULL,
  `total_bebida` decimal(10,2) DEFAULT 0.00,
  `total_comida` decimal(10,2) DEFAULT 0.00,
  `commission_rate` decimal(5,2) DEFAULT 0.00,
  `commission_value` decimal(10,2) DEFAULT 0.00,
  `total_value` decimal(10,2) DEFAULT 0.01,
  `repasse` decimal(10,2) DEFAULT 0.00,
  `items` int(11) DEFAULT 0,
  `items_json` longtext DEFAULT NULL,
  `closed_at` datetime DEFAULT NULL,
  `closed_date` date NOT NULL,
  `closed_time` varchar(5) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_date` (`closed_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Arquivo Histórico de Fechamentos
CREATE TABLE IF NOT EXISTS `closings_archive` (
  `id` char(32) NOT NULL,
  `backup_id` char(32) NOT NULL,
  `mesa_id` varchar(20) NOT NULL,
  `total_bebida` decimal(10,2) DEFAULT 0.00,
  `total_comida collection_rate` decimal(10,2) DEFAULT 0.00,
  `commission_rate` decimal(5,2) DEFAULT 0.00,
  `commission_value` decimal(10,2) DEFAULT 0.00,
  `total_value` decimal(10,2) DEFAULT 0.01,
  `repasse` decimal(10,2) DEFAULT 0.00,
  `items` int(11) DEFAULT 0,
  `items_json` longtext DEFAULT NULL,
  `closed_at` datetime DEFAULT NULL,
  `closed_date` date NOT NULL,
  `closed_time` varchar(5) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_backup` (`backup_id`),
  KEY `idx_date_arch` (`closed_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Tabela de Bloqueio de IP
CREATE TABLE IF NOT EXISTS `ip_blocklist` (
  `ip_address` varchar(45) NOT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `blocked_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `blocked_by` varchar(50) DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Registro de Tentativas de Login
CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `attempted_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `role_tried` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_ip_attempts` (`ip_address`,`attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Tabela de Pedidos (Abertos)
CREATE TABLE IF NOT EXISTS `orders` (
  `id` char(32) NOT NULL,
  `mesa_id` varchar(20) NOT NULL,
  `product_id` char(32) DEFAULT NULL,
  `product_name` varchar(100) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `category` enum('bebida','comida') NOT NULL,
  `qty` int(11) NOT NULL DEFAULT 1,
  `status` enum('open','closed') DEFAULT 'open',
  `created_by` varchar(20) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_mesa_open` (`mesa_id`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. Tabela de Produtos
CREATE TABLE IF NOT EXISTS `products` (
  `id` char(32) NOT NULL,
  `name` varchar(100) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `category` enum('bebida','comida') NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. Tabela de Usuários
CREATE TABLE IF NOT EXISTS `users` (
  `role` varchar(20) NOT NULL,
  `name` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `theme` varchar(10) DEFAULT 'dark',
  `pass_changed_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Usuários iniciais (A senha é "senha123" para ambos)
INSERT IGNORE INTO `users` (`role`, `name`, `password_hash`, `pass_changed_at`) VALUES
('dono', 'Proprietário', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', NOW()),
('parceiro', 'Cozinha/Parceiro', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', NOW());

COMMIT;
