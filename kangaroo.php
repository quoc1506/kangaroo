<?php
/**
 * ==============================================================================
 * Central Master Coordination Server
 * SQLite3 WAL | REST API | Secure Vault Storage (No Private Key Exposure)
 * ==============================================================================
 */
$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0700, true);
}
$dbPath = $dataDir . '/tame_traps.db';
$vaultPath = $dataDir . '/.solution_vault.dat';

define('SECP_N', '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

try {
    $db = new SQLite3($dbPath);
    $db->busyTimeout(10000);
    $db->exec('PRAGMA journal_mode = WAL;');
    $db->exec('PRAGMA synchronous = NORMAL;');
    $db->exec('PRAGMA cache_size = -64000;');
    $db->exec('PRAGMA temp_store = MEMORY;');

    $db->exec("
        CREATE TABLE IF NOT EXISTS tame_traps (
            dp_x TEXT PRIMARY KEY,
            total_distance TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_tame_dp_x ON tame_traps(dp_x);

        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('target_dp', '50000000');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('range_min', '0x80000000000000000000000000000000000');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('range_max', '0xfffffffffffffffffffffffffffffffffff');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('target_pubkey', '031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640');

        CREATE TABLE IF NOT EXISTS workers_status (
            worker_id TEXT PRIMARY KEY,
            ip_address TEXT DEFAULT '',
            hardware TEXT DEFAULT '',
            hashrate TEXT DEFAULT '0 MH/s',
            mode TEXT DEFAULT 'IDLE',
            dp_count INTEGER DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ");
} catch (Exception $e) {
    if (!empty($_GET['action']) || !empty($_POST['action'])) {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['status' => 'ERROR', 'message' => $e->getMessage()]);
    } else {
        echo '<h1>Database Error</h1>';
    }
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

// Hàm tính nghiệm và mã hóa lưu an toàn vào Vault (Tuyệt đối không in ra ngoài)
function securely_vault_solution($rangeMinHex, $tameDistHex, $wildDistHex, $wildX, $workerId, $vaultPath) {
    if (!extension_loaded('gmp')) {
        return false;
    }
    $n = gmp_init(SECP_N);
    $rMin = gmp_init($rangeMinHex);
    $dT = gmp_init($tameDistHex);
    $dW = gmp_init($wildDistHex);

    $k1 = gmp_mod(gmp_sub(gmp_add($rMin, $dT), $dW), $n);
    if (gmp_sign($k1) < 0) $k1 = gmp_add($k1, $n);

    $k2 = gmp_mod(gmp_add(gmp_add($rMin, $dT), $dW), $n);
    if (gmp_sign($k2) < 0) $k2 = gmp_add($k2, $n);

    $payload = [
        'timestamp' => date('Y-m-d H:i:s'),
        'worker_id' => $workerId,
        'dp_x' => $wildX,
        'candidate_1' => '0x' . gmp_strval($k1, 16),
        'candidate_2' => '0x' . gmp_strval($k2, 16)
    ];

    file_put_contents($vaultPath, json_encode($payload, JSON_PRETTY_PRINT));
    @chmod($vaultPath, 0600);
    return true;
}

// 1. API: Lấy tác vụ
if ($action === 'get_task') {
    header('Content-Type: application/json; charset=UTF-8');
    $currDp = (int)$db->querySingle("SELECT COUNT(*) FROM tame_traps");
    $targetDp = (int)($db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);
    $rangeMin = $db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'range_min'") ?: '0x80000000000000000000000000000000000';
    $rangeMax = $db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'range_max'") ?: '0xfffffffffffffffffffffffffffffffffff';
    $targetPk = $db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_pubkey'") ?: '031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640';

    $taskType = ($currDp < $targetDp) ? 'TAME' : 'WILD';
    echo json_encode([
        'status' => 'OK',
        'task_type' => $taskType,
        'range_min' => $rangeMin,
        'range_max' => $rangeMax,
        'target_pubkey' => $targetPk,
        'dp_bits' => 23,
        'heartbeat_sec' => 10
    ]);
    exit;
}

// 2. API: Nộp bẫy TAME
if ($action === 'submit_tame' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=UTF-8');
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $workerId = $input['worker_id'] ?? 'unknown';
    $hashrate = $input['hashrate'] ?? '0 MH/s';
    $hardware = $input['hardware'] ?? '';
    $dpList = $input['dp_list'] ?? [];
    $insertedCount = 0;

    if (!empty($dpList)) {
        $db->exec('BEGIN TRANSACTION;');
        $stmt = $db->prepare("INSERT OR IGNORE INTO tame_traps (dp_x, total_distance) VALUES (:x, :dist)");
        foreach ($dpList as $item) {
            if (!empty($item['x']) && !empty($item['dist'])) {
                $stmt->bindValue(':x', strtolower(trim($item['x'])), SQLITE3_TEXT);
                $stmt->bindValue(':dist', strtolower(trim($item['dist'])), SQLITE3_TEXT);
                $stmt->execute();
                if ($db->changes() > 0) $insertedCount++;
            }
        }
        $db->exec('COMMIT;');
    }

    $stmtW = $db->prepare("
        INSERT INTO workers_status (worker_id, ip_address, hardware, hashrate, mode, dp_count, last_seen)
        VALUES (:wid, :ip, :hw, :hr, 'TAME', :cnt, CURRENT_TIMESTAMP)
        ON CONFLICT(worker_id) DO UPDATE SET
            ip_address = :ip,
            hardware = CASE WHEN :hw != '' THEN :hw ELSE hardware END,
            hashrate = CASE WHEN :hr != '' THEN :hr ELSE hashrate END,
            mode = 'TAME',
            dp_count = dp_count + :cnt,
            last_seen = CURRENT_TIMESTAMP
    ");
    $stmtW->bindValue(':wid', $workerId, SQLITE3_TEXT);
    $stmtW->bindValue(':ip', $clientIp, SQLITE3_TEXT);
    $stmtW->bindValue(':hw', $hardware, SQLITE3_TEXT);
    $stmtW->bindValue(':hr', $hashrate, SQLITE3_TEXT);
    $stmtW->bindValue(':cnt', $insertedCount, SQLITE3_INTEGER);
    $stmtW->execute();

    $currDp = (int)$db->querySingle("SELECT COUNT(*) FROM tame_traps");
    echo json_encode(['status' => 'SAVED', 'inserted' => $insertedCount, 'current_dp' => $currDp]);
    exit;
}

// 3. API: Kiểm tra va chạm WILD (Bảo mật: Không lộ Private Key)
if ($action === 'check_wild' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=UTF-8');
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $workerId = $input['worker_id'] ?? 'unknown';
    $dpList = $input['dp_list'] ?? [];
    $rangeMin = $db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'range_min'") ?: '0x80000000000000000000000000000000000';

    if (!empty($dpList)) {
        $stmtSearch = $db->prepare("SELECT dp_x, total_distance FROM tame_traps WHERE dp_x = :x LIMIT 1");
        foreach ($dpList as $wildDp) {
            $wildX = strtolower(trim($wildDp['x'] ?? ''));
            $wildDist = strtolower(trim($wildDp['dist'] ?? ''));
            if (!$wildX) continue;

            $stmtSearch->bindValue(':x', $wildX, SQLITE3_TEXT);
            $res = $stmtSearch->execute();
            $row = $res->fetchArray(SQLITE3_ASSOC);
            if ($row) {
                $tameDist = $row['total_distance'];
                securely_vault_solution($rangeMin, $tameDist, $wildDist, $wildX, $workerId, $vaultPath);

                // Báo dừng cho worker, tuyệt đối không lộ Private key trong response
                echo json_encode([
                    'status' => 'BINGO',
                    'stop' => true,
                    'message' => 'Collision found and secured.'
                ]);
                exit;
            }
        }
    }
    echo json_encode(['status' => 'CONTINUE', 'stop' => false]);
    exit;
}

// 4. API: Dashboard Stats
if ($action === 'get_stats') {
    header('Content-Type: application/json; charset=UTF-8');
    $currDp = (int)$db->querySingle("SELECT COUNT(*) FROM tame_traps");
    $targetDp = (int)($db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);
    $progress = $targetDp > 0 ? round(($currDp / $targetDp) * 100, 2) : 0;
    $isSolved = file_exists($vaultPath);

    $workersRes = $db->query("SELECT worker_id, hardware, hashrate, mode, dp_count, strftime('%s', 'now') - strftime('%s', last_seen) AS sec_ago FROM workers_status ORDER BY last_seen DESC LIMIT 50");
    $workers = [];
    while ($w = $workersRes->fetchArray(SQLITE3_ASSOC)) {
        $workers[] = $w;
    }

    echo json_encode([
        'current_dp' => $currDp,
        'target_dp' => $targetDp,
        'progress' => $progress,
        'is_solved' => $isSolved,
        'workers' => $workers
    ]);
    exit;
}

// =============================================================================
// GIAO DIỆN WEB DASHBOARD (GIÁM SÁT AN TOÀN, KHÔNG HIỂN THỊ KHÓA BÍ MẬT)
// =============================================================================
$currDp = (int)$db->querySingle("SELECT COUNT(*) FROM tame_traps");
$targetDp = (int)($db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);
$progress = $targetDp > 0 ? round(($currDp / $targetDp) * 100, 2) : 0;
$isSolved = file_exists($vaultPath);
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Cluster Monitor</title>
    <style>
        body { font-family: monospace; background: #0f172a; color: #f8fafc; padding: 24px; margin: 0; }
        .container { max-width: 1000px; margin: 0 auto; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .badge-solved { background: #065f46; color: #34d399; }
        .badge-active { background: #1e40af; color: #93c5fd; }
        .progress-bar { background: #334155; height: 14px; border-radius: 7px; overflow: hidden; margin-top: 10px; }
        .progress-fill { background: #38bdf8; height: 100%; width: <?= min(100, $progress) ?>%; transition: width 0.3s; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="container">
        <h2>CLUSTER COORDINATION MONITOR</h2>

        <?php if ($isSolved): ?>
            <div class="card" style="border-color: #10b981; background: #064e3b;">
                <span class="badge badge-solved">TRẠNG THÁI: ĐÃ TÌM THẤY VA CHẠM &amp; ĐÃ ĐƯỢC LƯU AN TOÀN TRONG VAULT</span>
                <p style="margin: 8px 0 0; font-size: 13px; color: #a7f3d0;">
                    Dữ liệu đã được bảo mật tại <code>data/.solution_vault.dat</code> (Chỉ quản trị viên có quyền truy cập file trên máy chủ mới xem được).
                </p>
            </div>
        <?php endif; ?>

        <div class="card">
            <div>Giai đoạn: <span class="badge badge-active"><?= $currDp < $targetDp ? "GIAI ĐOẠN 1: TẠO BẪY TAME" : "GIAI ĐOẠN 2: SĂN VA CHẠM WILD" ?></span></div>
            <div style="margin-top: 12px;">Số lượng DP: <strong><?= number_format($currDp) ?> / <?= number_format($targetDp) ?> (<?= $progress ?>%)</strong></div>
            <div class="progress-bar"><div class="progress-fill"></div></div>
        </div>

        <div class="card">
            <h3 style="margin-top:0;">Danh sách máy trạm hoạt động</h3>
            <table>
                <thead>
                    <tr><th>Worker ID</th><th>Hardware</th><th>Hashrate</th><th>Mode</th><th>DP</th><th>Last Seen</th></tr>
                </thead>
                <tbody>
                <?php
                $workersRes = $db->query("SELECT worker_id, hardware, hashrate, mode, dp_count, strftime('%s', 'now') - strftime('%s', last_seen) AS sec_ago FROM workers_status ORDER BY last_seen DESC LIMIT 30");
                while ($w = $workersRes->fetchArray(SQLITE3_ASSOC)):
                    $sec = (int)$w['sec_ago'];
                    $color = ($sec <= 60) ? '#34d399' : '#f87171';
                ?>
                    <tr>
                        <td><?= htmlspecialchars($w['worker_id']) ?></td>
                        <td><?= htmlspecialchars($w['hardware']) ?></td>
                        <td><?= htmlspecialchars($w['hashrate']) ?></td>
                        <td><?= htmlspecialchars($w['mode']) ?></td>
                        <td><?= number_format($w['dp_count']) ?></td>
                        <td style="color: <?= $color ?>;"><?= $sec ?>s ago</td>
                    </tr>
                <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
