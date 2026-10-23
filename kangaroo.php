<?php
/**
 * Central Master Coordination Server
 * SQLite3 WAL | Binary BLOB Storage (WITHOUT ROWID) | 1,000 DP Batch Pipeline
 * Zero Private Key Exposure in Network / UI Logs | Dynamic Hit Probability
 */

error_reporting(0);
ini_set("display_errors", "0");
date_default_timezone_set("UTC");

$data_dir = __DIR__ . "/data";
if (!is_dir($data_dir)) {
    mkdir($data_dir, 0700, true);
}

$db_path = $data_dir . "/tame_traps.db";
$vault_path = $data_dir . "/.solution_vault.dat";

define("SECP_N", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
define("SPACE_WIDTH_140", "6.968e41"); // 2^139 = 696800000000000000000000000000000000000000

try {
    $db = new SQLite3($db_path);
    $db->busyTimeout(15000);
    $db->exec("PRAGMA journal_mode = WAL;");
    $db->exec("PRAGMA synchronous = NORMAL;");
    $db->exec("PRAGMA cache_size = -64000;");
    $db->exec("PRAGMA temp_store = MEMORY;");

    // Compact Binary BLOB Schema WITHOUT ROWID (64-byte payload per trap)
    $db->exec("
        CREATE TABLE IF NOT EXISTS tame_traps (
            dp_x BLOB PRIMARY KEY,
            total_distance BLOB NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_workers (
            worker_id TEXT PRIMARY KEY,
            hardware TEXT,
            hashrate TEXT,
            mode TEXT DEFAULT 'TAME',
            total_dps INTEGER DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('target_dp', '50000000');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('range_min', '0x80000000000000000000000000000000000');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('range_max', '0xfffffffffffffffffffffffffffffffffff');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('target_pubkey', '031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('dp_mask_bits', '23');
        INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('total_wild_steps', '0');
    ");
} catch (Exception $e) {
    http_response_code(500);
    header("Content-Type: application/json");
    echo json_encode(["status" => "ERROR", "message" => "Database initialization failed"]);
    exit;
}

function get_setting($db, $key, $default = "") {
    $stmt = $db->prepare("SELECT setting_value FROM system_settings WHERE setting_key = :k LIMIT 1;");
    $stmt->bindValue(":k", $key, SQLITE3_TEXT);
    $res = $stmt->execute();
    $row = $res ? $res->fetchArray(SQLITE3_ASSOC) : false;
    return $row ? $row["setting_value"] : $default;
}

function set_setting($db, $key, $value) {
    $stmt = $db->prepare("INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES (:k, :v);");
    $stmt->bindValue(":k", $key, SQLITE3_TEXT);
    $stmt->bindValue(":v", (string)$value, SQLITE3_TEXT);
    $stmt->execute();
}

/**
 * Solve private key for both symmetric curve candidates:
 * k1 = (RangeMin + D_T - D_W) mod n
 * k2 = (RangeMin + D_T + D_W) mod n
 */
function solve_candidate_keys($range_min_hex, $tame_dist_hex, $wild_dist_hex) {
    if (extension_loaded("gmp")) {
        $n = gmp_init(SECP_N, 16);
        $min = gmp_init($range_min_hex, 16);
        $dt = gmp_init($tame_dist_hex, 16);
        $dw = gmp_init($wild_dist_hex, 16);

        // Candidate 1: k1 = (range_min + dt - dw) mod n
        $diff1 = gmp_sub($dt, $dw);
        $k1 = gmp_add($min, $diff1);
        $k1 = gmp_mod($k1, $n);
        if (gmp_sign($k1) < 0) {
            $k1 = gmp_add($k1, $n);
        }

        // Candidate 2: k2 = (range_min + dt + dw) mod n
        $diff2 = gmp_add($dt, $dw);
        $k2 = gmp_add($min, $diff2);
        $k2 = gmp_mod($k2, $n);
        if (gmp_sign($k2) < 0) {
            $k2 = gmp_add($k2, $n);
        }

        return [
            "cand1" => "0x" . str_pad(gmp_strval($k1, 16), 64, "0", STR_PAD_LEFT),
            "cand2" => "0x" . str_pad(gmp_strval($k2, 16), 64, "0", STR_PAD_LEFT)
        ];
    } else {
        return [
            "cand1" => "0xRECORDED_CHECK_SECURE_VAULT",
            "cand2" => "0xRECORDED_CHECK_SECURE_VAULT"
        ];
    }
}

/**
 * Calculate dynamic hit probability based on Birthday Paradox / Kangaroo Walk
 * Space W = 2^139 ≈ 6.968e41
 * Each DP represents 2^23 steps (≈ 8,388,608 steps)
 */
function calculate_hit_probability($total_traps, $wild_steps = 0) {
    $dp_step = pow(2, 23); // 8388608
    $w = 6.968e41; // 2^139
    $tame_steps = (float)$total_traps * $dp_step;

    if ($wild_steps <= 0) {
        // If still in TAME phase or wild just starting, calculate potential collision probability
        // assuming balanced walks (Tame = Wild)
        $potential_p = ($tame_steps * $tame_steps) / (2.0 * $w);
        return [
            "mode" => "TAME_COVERAGE",
            "prob_numeric" => $potential_p,
            "prob_scientific" => sprintf("%.3e", $potential_p),
            "prob_percent" => sprintf("%.12f%%", $potential_p * 100.0),
            "odds_text" => ($potential_p > 0) ? "1 in " . sprintf("%.2e", 1.0 / $potential_p) : "N/A",
            "tame_steps_scientific" => sprintf("%.2e", $tame_steps)
        ];
    } else {
        // Active Wild phase collision probability: 1 - exp(- (T * W) / (2 * Space))
        $exponent = ($tame_steps * (float)$wild_steps) / (2.0 * $w);
        $prob = 1.0 - exp(-$exponent);
        return [
            "mode" => "WILD_ACTIVE",
            "prob_numeric" => $prob,
            "prob_scientific" => sprintf("%.3e", $prob),
            "prob_percent" => sprintf("%.12f%%", $prob * 100.0),
            "odds_text" => ($prob > 0) ? "1 in " . sprintf("%.2e", 1.0 / $prob) : "N/A",
            "tame_steps_scientific" => sprintf("%.2e", $tame_steps),
            "wild_steps_scientific" => sprintf("%.2e", (float)$wild_steps)
        ];
    }
}

$action = isset($_GET["action"]) ? $_GET["action"] : "";

// API 1: GET TASK
if ($action === "get_task") {
    header("Content-Type: application/json");
    $worker_id = isset($_GET["worker_id"]) ? $_GET["worker_id"] : "anon_node";
    $hardware = isset($_GET["hardware"]) ? $_GET["hardware"] : "Node";

    $res = $db->querySingle("SELECT COUNT(*) FROM tame_traps;");
    $tame_count = $res ? intval($res) : 0;
    $target_dp = intval(get_setting($db, "target_dp", "50000000"));

    $task_type = ($tame_count >= $target_dp) ? "WILD" : "TAME";

    echo json_encode([
        "status" => "OK",
        "task_type" => $task_type,
        "current_traps" => $tame_count,
        "target_traps" => $target_dp,
        "range_min" => get_setting($db, "range_min"),
        "range_max" => get_setting($db, "range_max"),
        "target_pubkey" => get_setting($db, "target_pubkey"),
        "dp_mask_bits" => intval(get_setting($db, "dp_mask_bits", "23")),
        "batch_limit" => 1000,
        "heartbeat_sec" => ($task_type === "WILD") ? 30 : 60
    ]);
    exit;
}

// API 2 & 3: SUBMIT TAME & CHECK WILD
if ($action === "submit_tame" || $action === "check_wild") {
    header("Content-Type: application/json");
    $input = file_get_contents("php://input");
    $payload = json_decode($input, true);

    if (!$payload || !isset($payload["dp_list"]) || !is_array($payload["dp_list"])) {
        echo json_encode(["status" => "ERROR", "message" => "Invalid payload"]);
        exit;
    }

    $worker_id = isset($payload["worker_id"]) ? $payload["worker_id"] : "anon";
    $hardware = isset($payload["hardware"]) ? $payload["hardware"] : "Node";
    $hashrate = isset($payload["hashrate"]) ? $payload["hashrate"] : "0.00 MH/s";
    $dp_list = $payload["dp_list"];
    $batch_size = count($dp_list);
    $current_mode = ($action === "check_wild") ? "WILD" : "TAME";

    // Update worker status
    $w_stmt = $db->prepare("INSERT INTO active_workers (worker_id, hardware, hashrate, mode, total_dps, last_seen)
                            VALUES (:wid, :hw, :hr, :mode, :dps, CURRENT_TIMESTAMP)
                            ON CONFLICT(worker_id) DO UPDATE SET
                                hardware = :hw,
                                hashrate = :hr,
                                mode = :mode,
                                total_dps = total_dps + :dps,
                                last_seen = CURRENT_TIMESTAMP;");
    $w_stmt->bindValue(":wid", $worker_id, SQLITE3_TEXT);
    $w_stmt->bindValue(":hw", $hardware, SQLITE3_TEXT);
    $w_stmt->bindValue(":hr", $hashrate, SQLITE3_TEXT);
    $w_stmt->bindValue(":mode", $current_mode, SQLITE3_TEXT);
    $w_stmt->bindValue(":dps", $batch_size, SQLITE3_INTEGER);
    $w_stmt->execute();

    if ($action === "submit_tame") {
        $db->exec("BEGIN TRANSACTION;");
        $ins = $db->prepare("INSERT OR IGNORE INTO tame_traps (dp_x, total_distance) VALUES (:x, :dist);");
        $saved = 0;

        foreach ($dp_list as $dp) {
            if (empty($dp["x"]) || empty($dp["dist"])) continue;
            $x_clean = str_pad(preg_replace('/^0[xX]/', '', trim($dp["x"])), 64, "0", STR_PAD_LEFT);
            $dist_clean = str_pad(preg_replace('/^0[xX]/', '', trim($dp["dist"])), 64, "0", STR_PAD_LEFT);
            $bin_x = hex2bin($x_clean);
            $bin_dist = hex2bin($dist_clean);

            if ($bin_x !== false && $bin_dist !== false) {
                $ins->bindValue(":x", $bin_x, SQLITE3_BLOB);
                $ins->bindValue(":dist", $bin_dist, SQLITE3_BLOB);
                $ins->execute();
                $saved++;
            }
        }
        $db->exec("COMMIT;");

        if ($saved >= 1000) {
            $db->exec("PRAGMA wal_checkpoint(PASSIVE);");
        }

        $total = intval($db->querySingle("SELECT COUNT(*) FROM tame_traps;"));
        $prob_info = calculate_hit_probability($total, 0);

        echo json_encode([
            "status" => "OK",
            "accepted" => $saved,
            "total_traps" => $total,
            "probability" => $prob_info["prob_scientific"]
        ]);
        exit;
    }

    if ($action === "check_wild") {
        // Increment wild steps counter
        $prev_wild = floatval(get_setting($db, "total_wild_steps", "0"));
        $added_steps = ($batch_size > 0) ? ($batch_size * pow(2, 23)) : 50000000; // estimated batch steps
        set_setting($db, "total_wild_steps", (string)($prev_wild + $added_steps));

        $chk = $db->prepare("SELECT total_distance FROM tame_traps WHERE dp_x = :x LIMIT 1;");
        $range_min = get_setting($db, "range_min");

        foreach ($dp_list as $dp) {
            if (empty($dp["x"]) || empty($dp["dist"])) continue;
            $x_clean = str_pad(preg_replace('/^0[xX]/', '', trim($dp["x"])), 64, "0", STR_PAD_LEFT);
            $bin_x = hex2bin($x_clean);
            if ($bin_x === false) continue;

            $chk->bindValue(":x", $bin_x, SQLITE3_BLOB);
            $res = $chk->execute();
            $row = $res ? $res->fetchArray(SQLITE3_ASSOC) : false;

            if ($row) {
                // COLLISION DETECTED!
                $tame_dist_hex = bin2hex($row["total_distance"]);
                $wild_dist_hex = str_pad(preg_replace('/^0[xX]/', '', trim($dp["dist"])), 64, "0", STR_PAD_LEFT);
                $cands = solve_candidate_keys($range_min, $tame_dist_hex, $wild_dist_hex);

                // Write to secure server vault (permissions 0600, never exposed in JSON response or UI)
                $vault_data = json_encode([
                    "puzzle" => "#140",
                    "timestamp_utc" => gmdate("Y-m-d H:i:s"),
                    "worker_id" => $worker_id,
                    "hardware" => $hardware,
                    "collision_dp_x" => "0x" . bin2hex($bin_x),
                    "candidate_1" => $cands["cand1"],
                    "candidate_2" => $cands["cand2"],
                    "tame_distance" => "0x" . $tame_dist_hex,
                    "wild_distance" => "0x" . $wild_dist_hex
                ], JSON_PRETTY_PRINT);

                file_put_contents($vault_path, $vault_data, LOCK_EX);
                chmod($vault_path, 0600);

                echo json_encode([
                    "status" => "BINGO",
                    "stop" => true,
                    "message" => "Collision solved. Result securely locked in server vault (.solution_vault.dat)."
                ]);
                exit;
            }
        }

        echo json_encode(["status" => "CONTINUE", "stop" => false, "checked" => $batch_size]);
        exit;
    }
}

// API 4: SET TARGET DP
if ($action === "set_target_dp") {
    header("Content-Type: application/json");
    $input = file_get_contents("php://input");
    $payload = json_decode($input, true);
    if (isset($payload["target_dp"])) {
        $val = intval($payload["target_dp"]);
        if ($val > 0) {
            set_setting($db, "target_dp", (string)$val);
            echo json_encode(["status" => "SUCCESS", "target_dp" => $val]);
            exit;
        }
    }
    echo json_encode(["status" => "ERROR", "message" => "Invalid target_dp"]);
    exit;
}

// API 5: GET STATS
if ($action === "get_stats") {
    header("Content-Type: application/json");
    $total_traps = intval($db->querySingle("SELECT COUNT(*) FROM tame_traps;"));
    $target_dp = intval(get_setting($db, "target_dp", "50000000"));
    $wild_steps = floatval(get_setting($db, "total_wild_steps", "0"));
    $prob = calculate_hit_probability($total_traps, $wild_steps);

    $workers_res = $db->query("SELECT * FROM active_workers ORDER BY last_seen DESC LIMIT 50;");
    $workers_list = [];
    while ($workers_res && ($w = $workers_res->fetchArray(SQLITE3_ASSOC))) {
        $workers_list[] = $w;
    }

    echo json_encode([
        "current_dp" => $total_traps,
        "target_dp" => $target_dp,
        "progress_pct" => round(($total_traps / max(1, $target_dp)) * 100, 2),
        "current_phase" => ($total_traps >= $target_dp) ? "WILD" : "TAME",
        "winning_probability" => $prob,
        "active_workers_count" => count($workers_list),
        "vault_solved" => file_exists($vault_path)
    ]);
    exit;
}

// Web Dashboard
$total_traps = intval($db->querySingle("SELECT COUNT(*) FROM tame_traps;"));
$target_dp = intval(get_setting($db, "target_dp", "50000000"));
$vault_exists = file_exists($vault_path);
$db_size_bytes = file_exists($db_path) ? filesize($db_path) : 0;
$db_size_mb = round($db_size_bytes / (1024 * 1024), 2);
$wild_steps = floatval(get_setting($db, "total_wild_steps", "0"));
$prob_info = calculate_hit_probability($total_traps, $wild_steps);

$workers_res = $db->query("SELECT * FROM active_workers ORDER BY last_seen DESC LIMIT 30;");
$workers = [];
while ($workers_res && ($w = $workers_res->fetchArray(SQLITE3_ASSOC))) {
    $workers[] = $w;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kangaroo Master Coordinator</title>
    <style>
        * { box-sizing: border-box; }
        body { background: #0b1120; color: #f1f5f9; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0; padding: 24px; }
        .container { max-width: 1100px; margin: 0 auto; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 700; }
        .badge-green { background: #065f46; color: #34d399; }
        .badge-amber { background: #78350f; color: #fbbf24; }
        .badge-blue { background: #1e3a8a; color: #60a5fa; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .stat-val { font-size: 22px; font-weight: 700; color: #38bdf8; margin-top: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; font-size: 13px; }
        th { color: #94a3b8; font-weight: 600; }
        .prob-box { background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 14px; margin-top: 10px; }
    </style>
</head>
<body>
<div class="container">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
        <div>
            <h2 style="margin: 0; color: #38bdf8;">Kangaroo Master Coordinator</h2>
            <div style="font-size: 12px; color: #64748b; margin-top: 2px;">Secp256k1 Distributed Solver | Puzzle #140 [2^139 .. 2^140 - 1]</div>
        </div>
        <div>
            <?php if ($total_traps < $target_dp): ?>
                <span class="badge badge-amber">PHASE 1: TAME TRAPS</span>
            <?php else: ?>
                <span class="badge badge-green">PHASE 2: WILD HUNTING</span>
            <?php endif; ?>
            <span class="badge badge-blue">SQLite WAL</span>
        </div>
    </div>

    <!-- Probability & Core Metrics -->
    <div class="grid">
        <div class="card">
            <div style="font-size: 12px; color: #94a3b8;">Total Tame Traps</div>
            <div class="stat-val"><?= number_format($total_traps) ?></div>
            <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Target: <?= number_format($target_dp) ?> DPs</div>
        </div>
        <div class="card">
            <div style="font-size: 12px; color: #94a3b8;">Xác Suất Trúng Giải Hiện Tại</div>
            <div class="stat-val" style="color: #34d399;"><?= $prob_info["prob_scientific"] ?></div>
            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Tỷ lệ: <?= $prob_info["odds_text"] ?></div>
        </div>
        <div class="card">
            <div style="font-size: 12px; color: #94a3b8;">Database Disk Usage</div>
            <div class="stat-val"><?= $db_size_mb ?> MB</div>
            <div style="font-size: 11px; color: #34d399; margin-top: 4px;">Compact 64-Byte BLOB</div>
        </div>
        <div class="card">
            <div style="font-size: 12px; color: #94a3b8;">Server Vault Status</div>
            <div class="stat-val">
                <?php if ($vault_exists): ?>
                    <span style="color: #4ade80;">SOLVED (0600)</span>
                <?php else: ?>
                    <span style="color: #94a3b8;">ARMED &amp; LISTENING</span>
                <?php endif; ?>
            </div>
            <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Zero Key Exposure</div>
        </div>
    </div>

    <!-- Probability Breakdown Card -->
    <div class="card">
        <h3 style="margin: 0 0 10px 0; font-size: 15px; color: #cbd5e1;">Phân Tích Toán Học Xác Suất Va Chạm (Birthday Paradox)</h3>
        <div class="prob-box">
            <div style="font-size: 13px; line-height: 1.6;">
                <strong>Không gian khóa:</strong> W = 2<sup>139</sup> ≈ 6.968 × 10<sup>41</sup> điểm.<br>
                <strong>Tame Traps tích lũy:</strong> <?= number_format($total_traps) ?> DPs (≈ <?= $prob_info["tame_steps_scientific"] ?> bước đi thực tế).<br>
                <strong>Xác suất va chạm hiện thời:</strong> <span style="color: #38bdf8; font-weight: 700;"><?= $prob_info["prob_percent"] ?></span> (<?= $prob_info["prob_scientific"] ?>).<br>
                <strong>Tỷ lệ cược kỳ vọng:</strong> <?= $prob_info["odds_text"] ?>.
            </div>
        </div>
    </div>

    <!-- Active Compute Nodes -->
    <div class="card">
        <h3 style="margin: 0 0 10px 0; font-size: 15px; color: #cbd5e1;">Active Compute Nodes (Workers)</h3>
        <?php if (empty($workers)): ?>
            <div style="color: #64748b; font-size: 13px;">Chưa có worker nào kết nối. Khởi chạy node với: <code>bash run.sh</code></div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>Worker ID</th>
                        <th>Hardware</th>
                        <th>Hashrate</th>
                        <th>Mode</th>
                        <th>DPs Sent</th>
                        <th>Last Ping</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($workers as $w): ?>
                        <tr>
                            <td style="color: #38bdf8; font-weight: 600;"><?= htmlspecialchars($w["worker_id"]) ?></td>
                            <td><?= htmlspecialchars($w["hardware"]) ?></td>
                            <td style="color: #34d399; font-weight: 600;"><?= htmlspecialchars($w["hashrate"]) ?></td>
                            <td><span class="badge <?= ($w["mode"] === 'WILD') ? 'badge-green' : 'badge-amber' ?>"><?= htmlspecialchars($w["mode"]) ?></span></td>
                            <td><?= number_format($w["total_dps"]) ?></td>
                            <td style="color: #94a3b8;"><?= htmlspecialchars($w["last_seen"]) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
</body>
</html>