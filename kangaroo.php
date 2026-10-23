<?php
/**
 * ==============================================================================
 * Central Master Coordination Server
 * SQLite3 WAL | REST API | Secure Vault Storage (No Private Key Exposure)
 * ==============================================================================
 */

 = __DIR__ . '/data';
if (!is_dir()) {
    mkdir(, 0700, true);
}

 =  . '/tame_traps.db';
 =  . '/.solution_vault.dat';
define('SECP_N', '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

try {
     = new SQLite3();
    ->busyTimeout(15000);
    ->exec('PRAGMA journal_mode = WAL;');
    ->exec('PRAGMA synchronous = NORMAL;');
    ->exec('PRAGMA cache_size = -64000;');
    ->exec('PRAGMA temp_store = MEMORY;');

    ->exec("
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
} catch (Exception ) {
    if (!empty(['action']) || !empty(['action'])) {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['status' => 'ERROR', 'message' => ->getMessage()]);
    } else {
        echo '<h1>Database Error</h1>';
    }
    exit;
}

 = ['action'] ?? ['action'] ?? '';
 = ['REMOTE_ADDR'] ?? '127.0.0.1';

// Tinh toan nghiem khoa bi mat va luu an toan tuyet doi vao vault (Khong xuat ra ngoai mang/dashboard)
function securely_vault_solution(, , , , , ) {
    if (!extension_loaded('gmp')) {
        return false;
    }
     = gmp_init(SECP_N);
     = gmp_init();
     = gmp_init();
     = gmp_init();

    // TH 1: P_T = P_W  => k1 = (RangeMin + D_T - D_W) mod n
     = gmp_mod(gmp_sub(gmp_add(, ), ), );
    if (gmp_sign() < 0)  = gmp_add(, );

    // TH 2: P_T = -P_W => k2 = (-RangeMin - D_T - D_W) mod n = n - ((RangeMin + D_T + D_W) mod n)
     = gmp_mod(gmp_add(gmp_add(, ), ), );
     = gmp_mod(gmp_sub(, ), );

     = [
        'timestamp' => date('Y-m-d H:i:s'),
        'worker_id' => ,
        'dp_x' => ,
        'candidate_1' => '0x' . gmp_strval(, 16),
        'candidate_2' => '0x' . gmp_strval(, 16)
    ];

    file_put_contents(, json_encode(, JSON_PRETTY_PRINT));
    @chmod(, 0600);
    return true;
}

// 1. API: Lay tac vu
if ( === 'get_task') {
    header('Content-Type: application/json; charset=UTF-8');
     = (int)->querySingle("SELECT COUNT(*) FROM tame_traps");
     = (int)(->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);
     = ->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'range_min'") ?: '0x80000000000000000000000000000000000';
     = ->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'range_max'") ?: '0xfffffffffffffffffffffffffffffffffff';
     = ->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_pubkey'") ?: '031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640';

     = ( < ) ? 'TAME' : 'WILD';

    echo json_encode([
        'status' => 'OK',
        'task_type' => ,
        'range_min' => ,
        'range_max' => ,
        'target_pubkey' => ,
        'dp_bits' => 23,
        'heartbeat_sec' => 10
    ]);
    exit;
}

// 2. API: Nop bay TAME
if ( === 'submit_tame' && ['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=UTF-8');
     = json_decode(file_get_contents('php://input'), true) ?? [];
     = ['worker_id'] ?? 'unknown';
     = ['hashrate'] ?? '0 MH/s';
     = ['hardware'] ?? '';
     = ['dp_list'] ?? [];

     = 0;
    if (!empty()) {
        ->exec('BEGIN TRANSACTION;');
         = ->prepare("INSERT OR IGNORE INTO tame_traps (dp_x, total_distance) VALUES (:x, :dist)");
        foreach ( as ) {
            if (!empty(['x']) && !empty(['dist'])) {
                ->bindValue(':x', strtolower(trim(['x'])), SQLITE3_TEXT);
                ->bindValue(':dist', strtolower(trim(['dist'])), SQLITE3_TEXT);
                ->execute();
                if (->changes() > 0) ++;
            }
        }
        ->exec('COMMIT;');
    }

     = ->prepare("
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
    ->bindValue(':wid', , SQLITE3_TEXT);
    ->bindValue(':ip', , SQLITE3_TEXT);
    ->bindValue(':hw', , SQLITE3_TEXT);
    ->bindValue(':hr', , SQLITE3_TEXT);
    ->bindValue(':cnt', , SQLITE3_INTEGER);
    ->execute();

     = (int)->querySingle("SELECT COUNT(*) FROM tame_traps");
    echo json_encode(['status' => 'SAVED', 'inserted' => , 'current_dp' => ]);
    exit;
}

// 3. API: Kiem tra va cham WILD (Bao mat: Khong lo Private Key tren kenh HTTP)
if ( === 'check_wild' && ['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=UTF-8');
     = json_decode(file_get_contents('php://input'), true) ?? [];
     = ['worker_id'] ?? 'unknown';
     = ['dp_list'] ?? [];
     = ['hashrate'] ?? '';
     = ['hardware'] ?? '';

    // Cap nhat worker status
     = ->prepare("
        INSERT INTO workers_status (worker_id, ip_address, hardware, hashrate, mode, dp_count, last_seen)
        VALUES (:wid, :ip, :hw, :hr, 'WILD', :cnt, CURRENT_TIMESTAMP)
        ON CONFLICT(worker_id) DO UPDATE SET
            ip_address = :ip,
            hardware = CASE WHEN :hw != '' THEN :hw ELSE hardware END,
            hashrate = CASE WHEN :hr != '' THEN :hr ELSE hashrate END,
            mode = 'WILD',
            dp_count = dp_count + :cnt,
            last_seen = CURRENT_TIMESTAMP
    ");
    ->bindValue(':wid', , SQLITE3_TEXT);
    ->bindValue(':ip', , SQLITE3_TEXT);
    ->bindValue(':hw', , SQLITE3_TEXT);
    ->bindValue(':hr', , SQLITE3_TEXT);
    ->bindValue(':cnt', count(), SQLITE3_INTEGER);
    ->execute();

     = ->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'range_min'") ?: '0x80000000000000000000000000000000000';

    if (!empty()) {
         = ->prepare("SELECT dp_x, total_distance FROM tame_traps WHERE dp_x = :x LIMIT 1");
        foreach ( as ) {
             = strtolower(trim(['x'] ?? ''));
             = strtolower(trim(['dist'] ?? ''));
            if (!) continue;

            ->bindValue(':x', , SQLITE3_TEXT);
             = ->execute();
             = ->fetchArray(SQLITE3_ASSOC);
            if () {
                 = ['total_distance'];
                securely_vault_solution(, , , , , );

                // Bao dung cho cluster, tuyet doi khong gui Private Key qua JSON
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
if ( === 'get_stats') {
    header('Content-Type: application/json; charset=UTF-8');
     = (int)->querySingle("SELECT COUNT(*) FROM tame_traps");
     = (int)(->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);
     =  > 0 ? round(( / ) * 100, 2) : 0;
     = file_exists();

     = ->query("SELECT worker_id, hardware, hashrate, mode, dp_count, strftime('%s', 'now') - strftime('%s', last_seen) AS sec_ago FROM workers_status ORDER BY last_seen DESC LIMIT 50");
     = [];
    while ( = ->fetchArray(SQLITE3_ASSOC)) {
        [] = ;
    }

    echo json_encode([
        'current_dp' => ,
        'target_dp' => ,
        'progress' => ,
        'is_solved' => ,
        'workers' => 
    ]);
    exit;
}

// 5. API: Cap nhat Target DP
if ( === 'set_target_dp' && ['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=UTF-8');
     = json_decode(file_get_contents('php://input'), true) ?? [];
     = (int)(['target_dp'] ?? 0);
    if ( > 0) {
         = ->prepare("UPDATE system_settings SET setting_value = :val WHERE setting_key = 'target_dp'");
        ->bindValue(':val', (string), SQLITE3_TEXT);
        ->execute();
        echo json_encode(['status' => 'UPDATED', 'target_dp' => ]);
    } else {
        echo json_encode(['status' => 'ERROR', 'message' => 'Invalid target']);
    }
    exit;
}

// =============================================================================
// GIAO DIEN WEB DASHBOARD (GIAM SAT AN TOAN, KHONG HIEN THI KHOA BI MAT)
// =============================================================================
 = (int)->querySingle("SELECT COUNT(*) FROM tame_traps");
 = (int)(->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);
 =  > 0 ? round(( / ) * 100, 2) : 0;
 = file_exists();
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
        .progress-fill { background: #38bdf8; height: 100%; width: <?= min(100, ) ?>%; transition: width 0.3s; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="container">
        <h2>CLUSTER COORDINATION MONITOR</h2>

        <?php if (): ?>
            <div class="card" style="border-color: #10b981; background: #064e3b;">
                <span class="badge badge-solved">TRANG THAI: DA TIM THAY VA CHAM &amp; DA DUOC LUU AN TOAN TRONG VAULT</span>
                <p style="margin: 8px 0 0; font-size: 13px; color: #a7f3d0;">
                    Du lieu da duoc bao mat tai <code>data/.solution_vault.dat</code> (Chi quan tri vien co quyen truy cap file tren server moi doc duoc).
                </p>
            </div>
        <?php endif; ?>

        <div class="card">
            <div>Giai doan: <span class="badge badge-active"><?=  <  ? "GIAI DOAN 1: TAO BAY TAME" : "GIAI DOAN 2: SAN VA CHAM WILD" ?></span></div>
            <div style="margin-top: 12px;">So luong DP: <strong><?= number_format() ?> / <?= number_format() ?> (<?=  ?>%)</strong></div>
            <div class="progress-bar"><div class="progress-fill"></div></div>
        </div>

        <div class="card">
            <h3 style="margin-top:0;">Danh sach may tram hoat dong</h3>
            <table>
                <thead>
                    <tr><th>Worker ID</th><th>Hardware</th><th>Hashrate</th><th>Mode</th><th>DP</th><th>Last Seen</th></tr>
                </thead>
                <tbody>
                <?php
                 = ->query("SELECT worker_id, hardware, hashrate, mode, dp_count, strftime('%s', 'now') - strftime('%s', last_seen) AS sec_ago FROM workers_status ORDER BY last_seen DESC LIMIT 30");
                while ( = ->fetchArray(SQLITE3_ASSOC)):
                     = (int)['sec_ago'];
                     = ( <= 60) ? '#34d399' : '#f87171';
                ?>
                    <tr>
                        <td><?= htmlspecialchars(['worker_id']) ?></td>
                        <td><?= htmlspecialchars(['hardware']) ?></td>
                        <td><?= htmlspecialchars(['hashrate']) ?></td>
                        <td><?= htmlspecialchars(['mode']) ?></td>
                        <td><?= number_format(['dp_count']) ?></td>
                        <td style="color: <?=  ?>;"><?=  ?>s ago</td>
                    </tr>
                <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
