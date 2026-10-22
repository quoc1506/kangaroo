<?php
/**
 * ==============================================================================
 * MASTER SERVER ALL-IN-ONE: kangaroo.php
 * Tích hợp trọn gói: Web Dashboard trực quan + REST API phân tán + Auto-Init SQLite WAL
 * Truy cập trực tiếp qua trình duyệt để xem Dashboard; gọi qua API cho Worker.
 * ==============================================================================
 */

$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0755, true);
}
$dbPath = $dataDir . '/tame_traps.db';

// Khởi tạo kết nối SQLite3 với chế độ WAL và tự động tạo bảng CSDL
try {
    $db = new SQLite3($dbPath);
    $db->busyTimeout(5000);
    $db->exec('PRAGMA journal_mode = WAL;');
    $db->exec('PRAGMA synchronous = NORMAL;');
    $db->exec('PRAGMA cache_size = -64000;');

    // Tự động tạo bảng nếu chưa có (Drop-in deployment không cần import SQL thủ công)
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
        http_response_code(500);
        echo json_encode(['status' => 'ERROR', 'message' => 'Database error: ' . $e->getMessage()]);
    } else {
        echo '<h1>Database Error</h1><p>' . htmlspecialchars($e->getMessage()) . '</p>';
    }
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

// =============================================================================
// GIAO DIỆN WEB DASHBOARD (Truy cập GET /kangaroo.php)
// =============================================================================
if (empty($action)) {
    header('Content-Type: text/html; charset=UTF-8');
    ?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Master Server Monitor - Kangaroo Secp256k1</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; font-feature-settings: 'tnum'; font-variant-numeric: tabular-nums; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-6 lg:p-8">

    <div class="max-w-7xl mx-auto space-y-6">
        <!-- Top Header -->
        <header class="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
            <div>
                <div class="flex items-center gap-3">
                    <span class="inline-block w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></span>
                    <h1 class="text-xl sm:text-2xl font-bold tracking-tight text-white">KANGAROO MASTER SERVER</h1>
                    <span id="phaseBadge" class="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                        LOADING...
                    </span>
                </div>
                <p class="text-xs sm:text-sm text-slate-400 mt-1 font-mono">
                    Hệ thống điều phối phân tán | SQLite 3 WAL | Secp256k1 Puzzle #140
                </p>
            </div>

            <div class="flex items-center gap-4 text-xs font-mono text-slate-400">
                <div>Cập nhật: <span id="lastUpdated" class="text-slate-200">--:--:--</span></div>
                <button onclick="fetchStats()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs transition border border-slate-700 cursor-pointer">
                    Làm mới
                </button>
            </div>
        </header>

        <!-- Metric Cards Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                <div class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Số lượng Bẫy TAME (DP)</div>
                <div class="text-2xl font-bold text-amber-400 font-mono" id="currentDp">0</div>
                <div class="mt-3">
                    <div class="flex justify-between text-xs text-slate-400 mb-1 font-mono">
                        <span>Tiến độ</span>
                        <span id="progressText">0%</span>
                    </div>
                    <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div id="progressBar" class="bg-gradient-to-r from-amber-500 to-emerald-500 h-2 rounded-full transition-all duration-500" style="width: 0%"></div>
                    </div>
                </div>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                <div class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Dung lượng Database</div>
                <div class="text-2xl font-bold text-cyan-400 font-mono" id="dbSize">0 MB</div>
                <div class="mt-3 flex items-center justify-between text-xs text-slate-400 font-mono border-t border-slate-800 pt-2">
                    <span>WAL: <span id="walSize" class="text-slate-300">0 MB</span></span>
                    <span>Đĩa: <span id="diskUsage" class="text-slate-300">-- GB</span></span>
                </div>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                <div class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Tổng Hashrate Cụm</div>
                <div class="text-2xl font-bold text-emerald-400 font-mono" id="totalHashrate">0 MH/s</div>
                <div class="mt-3 flex items-center justify-between text-xs text-slate-400 font-mono border-t border-slate-800 pt-2">
                    <span>Worker Online:</span>
                    <span id="activeWorkers" class="text-emerald-300 font-bold">0</span>
                </div>
            </div>

            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
                <div>
                    <div class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Mục tiêu Target DP</div>
                    <div class="text-2xl font-bold text-indigo-400 font-mono" id="targetDpDisplay">50,000,000</div>
                </div>
                <div class="mt-3 flex gap-2">
                    <input type="number" id="targetDpInput" placeholder="Số DP mới..." class="w-full bg-slate-950 border border-slate-700 text-xs text-slate-200 rounded-lg px-2.5 py-1.5 font-mono focus:outline-none focus:border-indigo-500">
                    <button onclick="updateTargetDp()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono px-3 py-1.5 rounded-lg transition shrink-0 cursor-pointer">
                        Lưu
                    </button>
                </div>
            </div>
        </div>

        <!-- Workers Table -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div class="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between">
                <h2 class="text-sm sm:text-base font-semibold text-white">Danh sách Máy trạm Worker</h2>
                <span class="text-xs font-mono text-slate-500">Tự động cập nhật mỗi 5 giây</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs font-mono">
                    <thead class="bg-slate-950/70 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
                        <tr>
                            <th class="py-3 px-4">Worker ID</th>
                            <th class="py-3 px-4">Phần cứng</th>
                            <th class="py-3 px-4">Địa chỉ IP</th>
                            <th class="py-3 px-4">Hashrate</th>
                            <th class="py-3 px-4">Chế độ</th>
                            <th class="py-3 px-4 text-right">DP Đã Nộp</th>
                            <th class="py-3 px-4">Tương tác cuối</th>
                            <th class="py-3 px-4 text-center">Trạng thái</th>
                        </tr>
                    </thead>
                    <tbody id="workersTableBody" class="divide-y divide-slate-800/60 text-slate-300">
                        <tr id="emptyWorkerRow">
                            <td colspan="8" class="text-center py-8 text-slate-500">
                                Chưa có worker nào kết nối. Hãy khởi chạy <code class="text-emerald-400">bash run.sh</code> trên máy trạm.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let isFetching = false;
        function getStatusBadgeHtml(status) {
            if (status === 'ONLINE') return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">ONLINE</span>';
            if (status === 'WARNING') return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">CHẬM</span>';
            return '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">MẤT KẾT NỐI</span>';
        }

        function updateWorkerRow(tr, w) {
            const cells = tr.children;
            if (cells[0].textContent !== w.worker_id) cells[0].textContent = w.worker_id;
            if (cells[1].textContent !== (w.hardware || 'N/A')) cells[1].textContent = (w.hardware || 'N/A');
            if (cells[2].textContent !== w.ip_address) cells[2].textContent = w.ip_address;
            if (cells[3].textContent !== w.hashrate) cells[3].textContent = w.hashrate;
            const modeText = w.mode === 'TAME' ? 'BẪY TAME' : 'SĂN WILD';
            if (cells[4].textContent !== modeText) cells[4].innerHTML = '<span class="' + (w.mode === 'TAME' ? 'text-amber-400' : 'text-emerald-400') + '">' + modeText + '</span>';
            const dpStr = Number(w.dp_count).toLocaleString();
            if (cells[5].textContent !== dpStr) cells[5].textContent = dpStr;
            const timeStr = w.last_seen_sec_ago + 's trước';
            if (cells[6].textContent !== timeStr) cells[6].textContent = timeStr;
            const badgeHtml = getStatusBadgeHtml(w.status);
            if (cells[7].innerHTML !== badgeHtml) cells[7].innerHTML = badgeHtml;
        }

        function createWorkerRow(w) {
            const tr = document.createElement('tr');
            tr.setAttribute('data-worker-id', w.worker_id);
            tr.className = 'hover:bg-slate-850/50 transition-colors';
            tr.innerHTML = 
                '<td class="py-3 px-4 font-bold text-white">' + w.worker_id + '</td>' +
                '<td class="py-3 px-4 text-slate-400">' + (w.hardware || 'N/A') + '</td>' +
                '<td class="py-3 px-4 text-slate-400">' + w.ip_address + '</td>' +
                '<td class="py-3 px-4 text-emerald-400 font-semibold">' + w.hashrate + '</td>' +
                '<td class="py-3 px-4">' + (w.mode === 'TAME' ? '<span class="text-amber-400">BẪY TAME</span>' : '<span class="text-emerald-400">SĂN WILD</span>') + '</td>' +
                '<td class="py-3 px-4 text-right text-slate-200 font-semibold">' + Number(w.dp_count).toLocaleString() + '</td>' +
                '<td class="py-3 px-4 text-slate-400">' + w.last_seen_sec_ago + 's trước</td>' +
                '<td class="py-3 px-4 text-center">' + getStatusBadgeHtml(w.status) + '</td>';
            return tr;
        }

        async function fetchStats() {
            if (isFetching) return;
            isFetching = true;
            try {
                const res = await fetch('kangaroo.php?action=get_stats');
                const data = await res.json();
                if (data.status !== 'OK') return;

                document.getElementById('currentDp').innerText = Number(data.current_dp).toLocaleString();
                document.getElementById('targetDpDisplay').innerText = Number(data.target_dp).toLocaleString();
                document.getElementById('progressText').innerText = data.progress_pct + '%';
                document.getElementById('progressBar').style.width = Math.min(data.progress_pct, 100) + '%';
                document.getElementById('dbSize').innerText = data.database_size_formatted;
                document.getElementById('walSize').innerText = data.wal_size_formatted;
                document.getElementById('diskUsage').innerText = data.disk_free_gb + ' / ' + data.disk_total_gb + ' GB';
                document.getElementById('totalHashrate').innerText = data.total_cluster_hashrate;
                document.getElementById('activeWorkers').innerText = data.active_workers_count;
                document.getElementById('lastUpdated').innerText = new Date().toLocaleTimeString();

                const badge = document.getElementById('phaseBadge');
                if (data.current_phase === 'TAME') {
                    badge.className = 'px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40';
                    badge.innerText = 'GIAI ĐOẠN 1: TẠO BẪY TAME';
                } else {
                    badge.className = 'px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 animate-pulse';
                    badge.innerText = 'GIAI ĐOẠN 2: SĂN VA CHẠM WILD';
                }

                const tbody = document.getElementById('workersTableBody');
                if (!data.workers || data.workers.length === 0) {
                    tbody.innerHTML = '<tr id="emptyWorkerRow"><td colspan="8" class="text-center py-8 text-slate-500">Chưa có worker nào kết nối. Hãy khởi chạy bash run.sh trên máy trạm.</td></tr>';
                    return;
                }
                const emptyRow = document.getElementById('emptyWorkerRow');
                if (emptyRow) emptyRow.remove();

                const incomingIds = new Set(data.workers.map(w => w.worker_id));
                const existingRows = Array.from(tbody.querySelectorAll('tr[data-worker-id]'));
                const rowMap = new Map();
                existingRows.forEach(row => {
                    const wid = row.getAttribute('data-worker-id');
                    if (!incomingIds.has(wid)) row.remove();
                    else rowMap.set(wid, row);
                });

                data.workers.forEach(w => {
                    if (rowMap.has(w.worker_id)) updateWorkerRow(rowMap.get(w.worker_id), w);
                    else tbody.appendChild(createWorkerRow(w));
                });
            } catch (err) {
                console.error(err);
            } finally {
                isFetching = false;
            }
        }

        async function updateTargetDp() {
            const input = document.getElementById('targetDpInput');
            const val = parseInt(input.value, 10);
            if (!val || val <= 0) {
                alert('Vui lòng nhập giá trị target_dp hợp lệ lớn hơn 0');
                return;
            }
            try {
                const res = await fetch('kangaroo.php?action=set_target_dp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target_dp: val })
                });
                const ret = await res.json();
                if (ret.status === 'SUCCESS') {
                    input.value = '';
                    fetchStats();
                } else {
                    alert('Lỗi cập nhật: ' + (ret.message || 'Thất bại'));
                }
            } catch (err) {
                alert('Không thể kết nối Master Server!');
            }
        }

        fetchStats();
        setInterval(fetchStats, 5000);
    </script>
</body>
</html>
    <?php
    exit;
}

// =============================================================================
// REST API HANDLERS (Khi có tham số action từ Worker hoặc Ajax)
// =============================================================================
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($action === 'get_task') {
    $workerId = trim($_GET['worker_id'] ?? 'unknown_worker');
    $currDp = (int)$db->querySingle("SELECT COUNT(*) FROM tame_traps");
    $targetDp = (int)($db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);

    $stmt = $db->prepare("
        INSERT INTO workers_status (worker_id, ip_address, last_seen) 
        VALUES (:wid, :ip, CURRENT_TIMESTAMP)
        ON CONFLICT(worker_id) DO UPDATE SET ip_address = :ip, last_seen = CURRENT_TIMESTAMP
    ");
    $stmt->bindValue(':wid', $workerId, SQLITE3_TEXT);
    $stmt->bindValue(':ip', $clientIp, SQLITE3_TEXT);
    $stmt->execute();

    if ($currDp < $targetDp) {
        echo json_encode([
            'status' => 'OK',
            'task_type' => 'TAME',
            'current_dp' => $currDp,
            'target_dp' => $targetDp,
            'range_min' => '0x80000000000000000000000000000000000',
            'range_max' => '0xfffffffffffffffffffffffffffffffffff',
            'dp_bits' => 23,
            'batch_limit' => 1000,
            'timeout_sec' => 60
        ]);
    } else {
        echo json_encode([
            'status' => 'OK',
            'task_type' => 'WILD',
            'current_dp' => $currDp,
            'target_dp' => $targetDp,
            'target_pubkey' => '031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640',
            'range_min' => '0x80000000000000000000000000000000000',
            'range_max' => '0xfffffffffffffffffffffffffffffffffff',
            'dp_bits' => 23,
            'heartbeat_sec' => 30
        ]);
    }
    exit;
}

if ($action === 'submit_tame' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input || empty($input['dp_list'])) {
        echo json_encode(['status' => 'EMPTY']);
        exit;
    }

    $workerId = $input['worker_id'] ?? 'unknown_worker';
    $hashrate = $input['hashrate'] ?? '0 MH/s';
    $hardware = $input['hardware'] ?? '';
    $dpList = $input['dp_list'];
    $insertedCount = 0;

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

    $stmtW = $db->prepare("
        INSERT INTO workers_status (worker_id, ip_address, hardware, hashrate, mode, dp_count, last_seen)
        VALUES (:wid, :ip, :hw, :hr, 'TAME', :cnt, CURRENT_TIMESTAMP)
        ON CONFLICT(worker_id) DO UPDATE SET
            ip_address = :ip,
            hardware = CASE WHEN :hw != '' THEN :hw ELSE hardware END,
            hashrate = :hr,
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
    echo json_encode([
        'status' => 'SAVED',
        'inserted' => $insertedCount,
        'current_dp' => $currDp
    ]);
    exit;
}

if ($action === 'check_wild' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $workerId = $input['worker_id'] ?? 'unknown_worker';
    $hashrate = $input['hashrate'] ?? '0 MH/s';
    $hardware = $input['hardware'] ?? '';
    $dpList = $input['dp_list'] ?? [];

    $stmtW = $db->prepare("
        INSERT INTO workers_status (worker_id, ip_address, hardware, hashrate, mode, last_seen)
        VALUES (:wid, :ip, :hw, :hr, 'WILD', CURRENT_TIMESTAMP)
        ON CONFLICT(worker_id) DO UPDATE SET
            ip_address = :ip,
            hardware = CASE WHEN :hw != '' THEN :hw ELSE hardware END,
            hashrate = :hr,
            mode = 'WILD',
            last_seen = CURRENT_TIMESTAMP
    ");
    $stmtW->bindValue(':wid', $workerId, SQLITE3_TEXT);
    $stmtW->bindValue(':ip', $clientIp, SQLITE3_TEXT);
    $stmtW->bindValue(':hw', $hardware, SQLITE3_TEXT);
    $stmtW->bindValue(':hr', $hashrate, SQLITE3_TEXT);
    $stmtW->execute();

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
                $collisionData = [
                    'timestamp' => date('Y-m-d H:i:s'),
                    'dp_x' => $wildX,
                    'wild_distance' => $wildDist,
                    'tame_distance' => $tameDist,
                    'worker_id' => $workerId
                ];
                file_put_contents($dataDir . '/collision_found.json', json_encode($collisionData, JSON_PRETTY_PRINT));
                echo json_encode([
                    'status' => 'BINGO',
                    'stop' => true,
                    'message' => 'Va chạm thành công! Dữ liệu đã lưu tại data/collision_found.json',
                    'data' => $collisionData
                ]);
                exit;
            }
        }
    }
    echo json_encode(['status' => 'CONTINUE', 'stop' => false]);
    exit;
}

if ($action === 'set_target_dp' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $newTarget = (int)($input['target_dp'] ?? 0);
    if ($newTarget > 0) {
        $stmt = $db->prepare("UPDATE system_settings SET setting_value = :val WHERE setting_key = 'target_dp'");
        $stmt->bindValue(':val', (string)$newTarget, SQLITE3_TEXT);
        $stmt->execute();
        echo json_encode(['status' => 'SUCCESS', 'target_dp' => $newTarget]);
    } else {
        echo json_encode(['status' => 'ERROR', 'message' => 'Giá trị target_dp không hợp lệ']);
    }
    exit;
}

if ($action === 'get_stats') {
    $currDp = (int)$db->querySingle("SELECT COUNT(*) FROM tame_traps");
    $targetDp = (int)($db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'target_dp'") ?: 50000000);
    $progressPct = ($targetDp > 0) ? round(($currDp / $targetDp) * 100, 2) : 0;
    $currentPhase = ($currDp < $targetDp) ? 'TAME' : 'WILD';

    $dbSizeBytes = file_exists($dbPath) ? filesize($dbPath) : 0;
    $walPath = $dbPath . '-wal';
    $walSizeBytes = file_exists($walPath) ? filesize($walPath) : 0;

    $formatBytes = function ($bytes) {
        if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . ' GB';
        if ($bytes >= 1048576) return round($bytes / 1048576, 2) . ' MB';
        if ($bytes >= 1024) return round($bytes / 1024, 2) . ' KB';
        return $bytes . ' B';
    };

    $diskFree = disk_free_space(__DIR__);
    $diskTotal = disk_total_space(__DIR__);

    $workersRes = $db->query("
        SELECT worker_id, ip_address, hardware, hashrate, mode, dp_count,
               strftime('%s', 'now') - strftime('%s', last_seen) AS sec_ago
        FROM workers_status
        ORDER BY last_seen DESC
    ");

    $workers = [];
    $activeCount = 0;
    $totalHashrateNum = 0;

    while ($w = $workersRes->fetchArray(SQLITE3_ASSOC)) {
        $secAgo = (int)$w['sec_ago'];
        $status = ($secAgo <= 60) ? 'ONLINE' : (($secAgo <= 180) ? 'WARNING' : 'OFFLINE');
        if ($status === 'ONLINE') {
            $activeCount++;
            if (preg_match('/([\d\.]+)/', $w['hashrate'], $m)) {
                $totalHashrateNum += (float)$m[1];
            }
        }
        $workers[] = [
            'worker_id' => $w['worker_id'],
            'ip_address' => $w['ip_address'],
            'hardware' => $w['hardware'],
            'hashrate' => $w['hashrate'],
            'mode' => $w['mode'],
            'dp_count' => (int)$w['dp_count'],
            'last_seen_sec_ago' => $secAgo,
            'status' => $status
        ];
    }

    echo json_encode([
        'status' => 'OK',
        'current_dp' => $currDp,
        'target_dp' => $targetDp,
        'progress_pct' => $progressPct,
        'current_phase' => $currentPhase,
        'database_size_bytes' => $dbSizeBytes,
        'database_size_formatted' => $formatBytes($dbSizeBytes),
        'wal_size_formatted' => $formatBytes($walSizeBytes),
        'disk_free_gb' => round($diskFree / (1024 * 1024 * 1024), 2),
        'disk_total_gb' => round($diskTotal / (1024 * 1024 * 1024), 2),
        'total_cluster_hashrate' => round($totalHashrateNum, 1) . ' MH/s',
        'active_workers_count' => $activeCount,
        'workers' => $workers
    ]);
    exit;
}

echo json_encode(['status' => 'INVALID_ACTION']);