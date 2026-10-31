<?php
/**
 * Central Master Coordination Server (100% Pure 64-bit PHP - Zero External Libraries)
 * SQLite3 WAL | 32-Shard Binary BLOB Storage (WITHOUT ROWID) | 1,000 DP Batch Pipeline
 * Native Pure-PHP 256-Bit BigInt & Secp256k1 Jacobian Verifier | Zero-Fallback & Zero-Dead-Code
 */

error_reporting(0);
ini_set("display_errors", "0");
date_default_timezone_set("UTC");
umask(0077);

if (PHP_INT_SIZE < 8) {
    http_response_code(500);
    header("Content-Type: application/json");
    echo json_encode(["status" => "ERROR", "message" => "64-bit PHP runtime is strictly required"]);
    exit;
}

if (!class_exists("SQLite3")) {
    http_response_code(500);
    header("Content-Type: application/json");
    echo json_encode(["status" => "ERROR", "message" => "PHP SQLite3 extension is strictly required"]);
    exit;
}

define("PHP_GUARD", "<?" . "php http_response_code(403); exit('403 Forbidden'); ?" . ">\n");
define("DEFAULT_SHARD_COUNT", 32);

class DbBusyException extends RuntimeException {}

/* ==========================================================================
 * 100% PURE PHP 256-BIT UNSIGNED ARITHMETIC & SECP256K1 ELLIPTIC CURVE ENGINE
 * ========================================================================== */

function u256_zero() {
    return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
}

function u256_from_int($v) {
    if (!is_int($v) || $v < 0) {
        throw new InvalidArgumentException("u256_from_int requires non-negative integer");
    }
    $out = u256_zero();
    $i = 0;
    while ($v > 0 && $i < 16) {
        $out[$i] = $v & 0xFFFF;
        $v >>= 16;
        $i++;
    }
    return $out;
}

function u256_from_hex($hex) {
    $s = trim((string)$hex);
    if (strncmp($s, "0x", 2) === 0 || strncmp($s, "0X", 2) === 0) {
        $s = substr($s, 2);
    }
    if ($s === "" || !preg_match('/^[0-9a-fA-F]+$/', $s)) {
        throw new InvalidArgumentException("Invalid hexadecimal u256 input");
    }
    $trimmed = ltrim($s, "0");
    if ($trimmed === "") {
        return u256_zero();
    }
    if (strlen($trimmed) > 64) {
        throw new InvalidArgumentException("Hexadecimal value exceeds 256 bits");
    }
    $padded = str_pad($trimmed, 64, "0", STR_PAD_LEFT);
    $out = u256_zero();
    for ($i = 0; $i < 16; $i++) {
        $out[$i] = hexdec(substr($padded, 60 - ($i * 4), 4));
    }
    return $out;
}

function u256_to_hex($a) {
    $parts = [];
    for ($i = 15; $i >= 0; $i--) {
        $parts[] = sprintf("%04x", $a[$i]);
    }
    return implode("", $parts);
}

function u256_is_zero($a) {
    for ($i = 0; $i < 16; $i++) {
        if ($a[$i] !== 0) {
            return false;
        }
    }
    return true;
}

function u256_cmp($a, $b) {
    for ($i = 15; $i >= 0; $i--) {
        if ($a[$i] !== $b[$i]) {
            return ($a[$i] > $b[$i]) ? 1 : -1;
        }
    }
    return 0;
}

function u256_bit_length($a) {
    for ($i = 15; $i >= 0; $i--) {
        if ($a[$i] !== 0) {
            $v = $a[$i];
            $bits = 0;
            while ($v > 0) {
                $bits++;
                $v >>= 1;
            }
            return ($i * 16) + $bits;
        }
    }
    return 0;
}

function u256_to_float($a) {
    $val = 0.0;
    for ($i = 15; $i >= 0; $i--) {
        $val = ($val * 65536.0) + (float)$a[$i];
    }
    return $val;
}

function u256_add($a, $b) {
    $out = u256_zero();
    $carry = 0;
    for ($i = 0; $i < 16; $i++) {
        $sum = $a[$i] + $b[$i] + $carry;
        $out[$i] = $sum & 0xFFFF;
        $carry = $sum >> 16;
    }
    return [$out, $carry];
}

function u256_sub($a, $b) {
    $out = u256_zero();
    $borrow = 0;
    for ($i = 0; $i < 16; $i++) {
        $diff = $a[$i] - $b[$i] - $borrow;
        if ($diff < 0) {
            $diff += 0x10000;
            $borrow = 1;
        } else {
            $borrow = 0;
        }
        $out[$i] = $diff;
    }
    return [$out, $borrow];
}

function u256_shr1($a, $top_carry = 0) {
    $out = u256_zero();
    for ($i = 0; $i < 15; $i++) {
        $out[$i] = (($a[$i] >> 1) | (($a[$i + 1] & 1) << 15)) & 0xFFFF;
    }
    $out[15] = (($a[15] >> 1) | (($top_carry & 1) << 15)) & 0xFFFF;
    return $out;
}

function secp256k1_params() {
    static $params = null;
    if ($params === null) {
        $params = [
            "P" => u256_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
            "N" => u256_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            "GX" => u256_from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            "GY" => u256_from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
            "ONE" => u256_from_int(1)
        ];
    }
    return $params;
}

function fp_add($a, $b, $P) {
    list($r, $c) = u256_add($a, $b);
    if ($c > 0 || u256_cmp($r, $P) >= 0) {
        list($r, $_) = u256_sub($r, $P);
    }
    return $r;
}

function fp_sub($a, $b, $P) {
    list($r, $borrow) = u256_sub($a, $b);
    if ($borrow > 0) {
        list($r, $_) = u256_add($r, $P);
    }
    return $r;
}

function fp_mul($a, $b, $P) {
    $t = array_fill(0, 32, 0);
    for ($i = 0; $i < 16; $i++) {
        $ai = $a[$i];
        if ($ai === 0) {
            continue;
        }
        for ($j = 0; $j < 16; $j++) {
            $t[$i + $j] += $ai * $b[$j];
        }
    }

    for ($i = 16; $i < 32; $i++) {
        $h = $t[$i];
        if ($h !== 0) {
            $t[$i] = 0;
            $t[$i - 16] += $h * 977;
            $t[$i - 14] += $h;
        }
    }

    $c = 0;
    for ($i = 0; $i < 18; $i++) {
        $v = $t[$i] + $c;
        $t[$i] = $v & 0xFFFF;
        $c = $v >> 16;
    }
    $t[18] += $c;

    for ($i = 16; $i <= 18; $i++) {
        $h = $t[$i];
        if ($h !== 0) {
            $t[$i] = 0;
            $t[$i - 16] += $h * 977;
            $t[$i - 14] += $h;
        }
    }

    $out = u256_zero();
    $c = 0;
    for ($i = 0; $i < 16; $i++) {
        $v = $t[$i] + $c;
        $out[$i] = $v & 0xFFFF;
        $c = $v >> 16;
    }

    if ($c > 0) {
        $v0 = $out[0] + ($c * 977);
        $out[0] = $v0 & 0xFFFF;
        $c2 = $v0 >> 16;

        $v1 = $out[1] + $c2;
        $out[1] = $v1 & 0xFFFF;
        $c2 = $v1 >> 16;

        $v2 = $out[2] + $c + $c2;
        $out[2] = $v2 & 0xFFFF;
        $c2 = $v2 >> 16;

        $idx = 3;
        while ($c2 > 0 && $idx < 16) {
            $vi = $out[$idx] + $c2;
            $out[$idx] = $vi & 0xFFFF;
            $c2 = $vi >> 16;
            $idx++;
        }
        if ($c2 > 0) {
            list($out, $_) = u256_sub($out, $P);
        }
    }

    if (u256_cmp($out, $P) >= 0) {
        list($out, $_) = u256_sub($out, $P);
    }
    return $out;
}

function fp_inv($a, $P, $ONE) {
    if (u256_is_zero($a)) {
        throw new InvalidArgumentException("Modular inverse of zero does not exist");
    }
    $u = $a;
    $v = $P;
    $x1 = $ONE;
    $x2 = u256_zero();

    while (u256_cmp($u, $ONE) !== 0 && u256_cmp($v, $ONE) !== 0) {
        while (($u[0] & 1) === 0) {
            $u = u256_shr1($u, 0);
            if (($x1[0] & 1) === 0) {
                $x1 = u256_shr1($x1, 0);
            } else {
                list($s, $c) = u256_add($x1, $P);
                $x1 = u256_shr1($s, $c);
            }
        }
        while (($v[0] & 1) === 0) {
            $v = u256_shr1($v, 0);
            if (($x2[0] & 1) === 0) {
                $x2 = u256_shr1($x2, 0);
            } else {
                list($s, $c) = u256_add($x2, $P);
                $x2 = u256_shr1($s, $c);
            }
        }
        if (u256_cmp($u, $v) >= 0) {
            list($u, $_) = u256_sub($u, $v);
            $x1 = fp_sub($x1, $x2, $P);
        } else {
            list($v, $_) = u256_sub($v, $u);
            $x2 = fp_sub($x2, $x1, $P);
        }
    }

    $res = (u256_cmp($u, $ONE) === 0) ? $x1 : $x2;
    if (u256_cmp($res, $P) >= 0) {
        list($res, $_) = u256_sub($res, $P);
    }
    return $res;
}

function fn_mod($a, $N) {
    if (u256_cmp($a, $N) >= 0) {
        list($r, $_) = u256_sub($a, $N);
        return $r;
    }
    return $a;
}

function fn_add($a, $b, $N) {
    list($r, $c) = u256_add($a, $b);
    if ($c > 0 || u256_cmp($r, $N) >= 0) {
        list($r, $_) = u256_sub($r, $N);
    }
    return $r;
}

function fn_sub($a, $b, $N) {
    if (u256_cmp($a, $b) >= 0) {
        list($r, $_) = u256_sub($a, $b);
        return $r;
    }
    list($s, $_c) = u256_add($a, $N);
    list($r, $_b) = u256_sub($s, $b);
    return $r;
}

function fn_neg($a, $N) {
    if (u256_is_zero($a)) {
        return u256_zero();
    }
    list($r, $_) = u256_sub($N, $a);
    return $r;
}

function secp256k1_jac_double($pt, $P) {
    if ($pt === null) {
        return null;
    }
    list($X1, $Y1, $Z1) = $pt;
    if (u256_is_zero($Y1) || u256_is_zero($Z1)) {
        return null;
    }
    $Y1sq = fp_mul($Y1, $Y1, $P);
    $two_Y1sq = fp_add($Y1sq, $Y1sq, $P);
    $four_Y1sq = fp_add($two_Y1sq, $two_Y1sq, $P);
    $S = fp_mul($X1, $four_Y1sq, $P);

    $X1sq = fp_mul($X1, $X1, $P);
    $M = fp_add(fp_add($X1sq, $X1sq, $P), $X1sq, $P);

    $X3 = fp_sub(fp_mul($M, $M, $P), fp_add($S, $S, $P), $P);

    $Y1_4 = fp_mul($Y1sq, $Y1sq, $P);
    $two_Y1_4 = fp_add($Y1_4, $Y1_4, $P);
    $four_Y1_4 = fp_add($two_Y1_4, $two_Y1_4, $P);
    $eight_Y1_4 = fp_add($four_Y1_4, $four_Y1_4, $P);

    $Y3 = fp_sub(fp_mul($M, fp_sub($S, $X3, $P), $P), $eight_Y1_4, $P);
    $two_Y1 = fp_add($Y1, $Y1, $P);
    $Z3 = fp_mul($two_Y1, $Z1, $P);
    return [$X3, $Y3, $Z3];
}

function secp256k1_jac_add_affine($pt, $gx, $gy, $P, $ONE) {
    if ($pt === null) {
        return [$gx, $gy, $ONE];
    }
    list($X1, $Y1, $Z1) = $pt;
    if (u256_is_zero($Z1)) {
        return [$gx, $gy, $ONE];
    }
    $Z1sq = fp_mul($Z1, $Z1, $P);
    $Z1cu = fp_mul($Z1sq, $Z1, $P);
    $U2 = fp_mul($gx, $Z1sq, $P);
    $S2 = fp_mul($gy, $Z1cu, $P);

    if (u256_cmp($X1, $U2) === 0) {
        if (u256_cmp($Y1, $S2) === 0) {
            return secp256k1_jac_double($pt, $P);
        }
        return null;
    }

    $H = fp_sub($U2, $X1, $P);
    $R = fp_sub($S2, $Y1, $P);
    $H2 = fp_mul($H, $H, $P);
    $H3 = fp_mul($H2, $H, $P);
    $X1H2 = fp_mul($X1, $H2, $P);

    $X3 = fp_sub(fp_sub(fp_mul($R, $R, $P), $H3, $P), fp_add($X1H2, $X1H2, $P), $P);
    $Y3 = fp_sub(fp_mul($R, fp_sub($X1H2, $X3, $P), $P), fp_mul($Y1, $H3, $P), $P);
    $Z3 = fp_mul($Z1, $H, $P);
    return [$X3, $Y3, $Z3];
}

function secp256k1_derive_pubkey_pair($priv_u256) {
    $params = secp256k1_params();
    $k = fn_mod($priv_u256, $params["N"]);
    $blen = u256_bit_length($k);
    if ($blen === 0) {
        return null;
    }

    $P = $params["P"];
    $GX = $params["GX"];
    $GY = $params["GY"];
    $ONE = $params["ONE"];

    $res = null;
    for ($bit = $blen - 1; $bit >= 0; $bit--) {
        $res = secp256k1_jac_double($res, $P);
        $limb = $k[$bit >> 4];
        if ((($limb >> ($bit & 15)) & 1) === 1) {
            $res = secp256k1_jac_add_affine($res, $GX, $GY, $P, $ONE);
        }
    }
    if ($res === null) {
        return null;
    }

    list($X, $Y, $Z) = $res;
    $zinv = fp_inv($Z, $P, $ONE);
    $zinv2 = fp_mul($zinv, $zinv, $P);
    $zinv3 = fp_mul($zinv2, $zinv, $P);
    $ax = fp_mul($X, $zinv2, $P);
    $ay = fp_mul($Y, $zinv3, $P);

    $x_hex = u256_to_hex($ax);
    $y_hex = u256_to_hex($ay);
    $prefix = (($ay[0] & 1) === 1) ? "03" : "02";

    return [
        "compressed" => $prefix . $x_hex,
        "uncompressed" => "04" . $x_hex . $y_hex
    ];
}

/**
 * Pure-PHP private key recovery & cryptographic curve verification:
 * k1 = (D_T - D_W) mod n
 * k2 = (-D_T - D_W) mod n
 * Strictly verifies k * G == target_pubkey AND range_min <= k <= range_max
 */
function solve_candidate_keys($range_min_hex, $range_max_hex, $tame_dist_hex, $wild_dist_hex, $target_pubkey_hex) {
    $params = secp256k1_params();
    $N = $params["N"];
    $target_clean = strtolower(trim((string)$target_pubkey_hex));
    if (strncmp($target_clean, "0x", 2) === 0) {
        $target_clean = substr($target_clean, 2);
    }
    if (!preg_match('/^(02|03)[0-9a-f]{64}$/', $target_clean) && !preg_match('/^04[0-9a-f]{128}$/', $target_clean)) {
        throw new InvalidArgumentException("Invalid target_pubkey format");
    }
    $pub_fmt = (strlen($target_clean) === 66) ? "compressed" : "uncompressed";
    $min = u256_from_hex($range_min_hex);
    $max = u256_from_hex($range_max_hex);
    $dt = fn_mod(u256_from_hex($tame_dist_hex), $N);
    $dw = fn_mod(u256_from_hex($wild_dist_hex), $N);

    // 4-way Equivalence Symmetry Candidates
    $candidates = [
        fn_sub($dt, $dw, $N),
        fn_sub(fn_neg($dt, $N), $dw, $N),
        fn_add($dt, $dw, $N),
        fn_sub(fn_neg($dt, $N), fn_neg($dw, $N), $N)
    ];

    $verified_key = "";
    $derived_pubkey = "";
    $is_verified = false;

    foreach ($candidates as $k_cand) {
        $cand_in_range = (u256_cmp($k_cand, $min) >= 0 && u256_cmp($k_cand, $max) <= 0);
        if (!$cand_in_range) continue;
        $pair = secp256k1_derive_pubkey_pair($k_cand);
        $pub = ($pair !== null) ? $pair[$pub_fmt] : "";
        if ($pub !== "" && hash_equals($target_clean, $pub)) {
            $is_verified = true;
            $verified_key = "0x" . u256_to_hex($k_cand);
            $derived_pubkey = $pub;
            break;
        }
    }

    $c1_hex = "0x" . u256_to_hex($candidates[0]);
    $c2_hex = "0x" . u256_to_hex($candidates[1]);
    $c1_in_range = (u256_cmp($candidates[0], $min) >= 0 && u256_cmp($candidates[0], $max) <= 0);
    $c2_in_range = (u256_cmp($candidates[1], $min) >= 0 && u256_cmp($candidates[1], $max) <= 0);

    return [
        "cand1" => $c1_hex,
        "cand2" => $c2_hex,
        "cand1_in_range" => $c1_in_range,
        "cand2_in_range" => $c2_in_range,
        "is_verified" => $is_verified,
        "verified_key" => $verified_key,
        "derived_pubkey" => $derived_pubkey
    ];
}

function get_space_width_float($range_min_hex, $range_max_hex) {
    $min = u256_from_hex($range_min_hex);
    $max = u256_from_hex($range_max_hex);
    if (u256_cmp($max, $min) < 0) {
        throw new RuntimeException("Invalid search range: range_max cannot be less than range_min");
    }
    list($diff, $_) = u256_sub($max, $min);
    list($cardinality, $carry) = u256_add($diff, u256_from_int(1));
    $w = u256_to_float($cardinality) + ($carry > 0 ? pow(2.0, 256) : 0.0);
    if ($w <= 0.0 || is_infinite($w) || is_nan($w)) {
        throw new RuntimeException("Invalid search space width calculation");
    }
    return $w;
}

/* ==========================================================================
 * STORAGE, SHARDED SQLITE3 ENGINE & STRICT ATOMIC STATE HELPERS
 * ========================================================================== */

function protect_storage_dir($dir) {
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException("Failed to create storage directory");
        }
        if (!chmod($dir, 0700)) {
            throw new RuntimeException("Failed to set permissions on storage directory");
        }
    }
    if (!is_writable($dir)) {
        throw new RuntimeException("Storage directory is not writable");
    }
    $ht = $dir . "/.htaccess";
    if (!file_exists($ht)) {
        if (file_put_contents($ht, "Require all denied\nDeny from all\n", LOCK_EX) === false || !chmod($ht, 0600)) {
            throw new RuntimeException("Failed to write .htaccess guard");
        }
    }
    $idx = $dir . "/index.php";
    if (!file_exists($idx)) {
        if (file_put_contents($idx, PHP_GUARD, LOCK_EX) === false || !chmod($idx, 0600)) {
            throw new RuntimeException("Failed to write index.php guard");
        }
    }
}

function purge_verify_db($base_data_dir) {
    $suffixes = ["", "-wal", "-shm", "-journal"];
    foreach ($suffixes as $sfx) {
        $f = $base_data_dir . "/verify.db" . $sfx;
        if (file_exists($f) && !unlink($f)) {
            throw new RuntimeException("Unable to delete temporary verification file: verify.db" . $sfx);
        }
    }
}

function get_shard_db($shard_byte, $create_if_missing = true) {
    global $is_verify_mode, $db, $shards_dir, $active_shard_mask, $active_shard_count;
    if ($is_verify_mode) {
        return $db;
    }
    static $shard_handles = [];
    $idx = (is_int($shard_byte) ? $shard_byte : ord($shard_byte)) & $active_shard_mask;
    $hex = str_pad(dechex($idx), 2, "0", STR_PAD_LEFT);
    if (isset($shard_handles[$hex])) {
        return $shard_handles[$hex];
    }
    $path = $shards_dir . "/traps_" . $hex . ".db";
    if (!$create_if_missing) {
        clearstatcache(true, $path);
        if (!is_file($path) || filesize($path) === 0) {
            return null;
        }
    }
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $sdb = null;
        try {
            clearstatcache(true, $path);
            $needs_init = (!is_file($path) || filesize($path) === 0);
            $sdb = new SQLite3($path);
            $sdb->enableExceptions(true);
            $sdb->busyTimeout(30000);
            if ($needs_init) {
                if (!chmod($path, 0600)) {
                    throw new RuntimeException("Failed to secure shard database permissions");
                }
                $sdb->exec("PRAGMA page_size = 8192; PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL;");
                $sdb->exec("CREATE TABLE IF NOT EXISTS tame_traps (
                    dp_x BLOB PRIMARY KEY,
                    total_distance BLOB NOT NULL
                ) WITHOUT ROWID;");
            }
            $cache_kb = ($active_shard_count <= 32) ? "-4096" : "-2048";
            $mmap_bytes = ($active_shard_count <= 32) ? "67108864" : "33554432";
            $sdb->exec("PRAGMA synchronous = NORMAL; PRAGMA wal_autocheckpoint = 2000; PRAGMA cache_size = " . $cache_kb . "; PRAGMA mmap_size = " . $mmap_bytes . "; PRAGMA temp_store = MEMORY;");
            $shard_handles[$hex] = $sdb;
            return $sdb;
        } catch (Throwable $ex) {
            if ($sdb) {
                try { $sdb->close(); } catch (Throwable $_cl) {}
            }
            if ($attempt === 4) {
                throw new DbBusyException("Shard database busy during open: traps_" . $hex . ".db");
            }
            usleep(15000 * ($attempt + 1));
        }
    }
    throw new DbBusyException("Shard database busy during open: traps_" . $hex . ".db");
}

function find_setting_or_null($db, $key) {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $stmt = null;
        try {
            $stmt = $db->prepare("SELECT setting_value FROM system_settings WHERE setting_key = :k LIMIT 1;");
            $stmt->bindValue(":k", $key, SQLITE3_TEXT);
            $res = $stmt->execute();
            $row = $res->fetchArray(SQLITE3_ASSOC);
            $res->finalize();
            $stmt->close();
            return ($row !== false) ? (string)$row["setting_value"] : null;
        } catch (Throwable $ex) {
            if ($stmt) {
                $stmt->close();
            }
            if ($attempt === 4) {
                throw new DbBusyException("Database busy while reading setting: " . $key);
            }
            usleep(15000 * ($attempt + 1));
        }
    }
    throw new DbBusyException("Database busy while reading setting: " . $key);
}

function get_required_setting($db, $key) {
    $val = find_setting_or_null($db, $key);
    if ($val === null) {
        throw new RuntimeException("Required system setting missing: " . $key);
    }
    return $val;
}

function set_setting($db, $key, $value) {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $stmt = null;
        try {
            $stmt = $db->prepare("INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES (:k, :v);");
            $stmt->bindValue(":k", $key, SQLITE3_TEXT);
            $stmt->bindValue(":v", (string)$value, SQLITE3_TEXT);
            $stmt->execute();
            $stmt->close();
            return;
        } catch (Throwable $ex) {
            if ($stmt) {
                $stmt->close();
            }
            if ($attempt === 4) {
                throw new DbBusyException("Database busy while updating setting: " . $key);
            }
            usleep(15000 * ($attempt + 1));
        }
    }
}

function increment_setting_int($db, $key, $delta) {
    if ($delta === 0) {
        return intval(get_required_setting($db, $key));
    }
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $in_tx = false;
        $stmt = null;
        $q = null;
        try {
            $db->exec("BEGIN IMMEDIATE TRANSACTION;");
            $in_tx = true;
            $stmt = $db->prepare("INSERT INTO system_settings (setting_key, setting_value)
                VALUES (:k, CAST(:d AS TEXT))
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = CAST(CAST(setting_value AS INTEGER) + :d AS TEXT);");
            $stmt->bindValue(":k", $key, SQLITE3_TEXT);
            $stmt->bindValue(":d", (int)$delta, SQLITE3_INTEGER);
            $stmt->execute();
            $stmt->close();
            $stmt = null;

            $q = $db->prepare("SELECT setting_value FROM system_settings WHERE setting_key = :k LIMIT 1;");
            $q->bindValue(":k", $key, SQLITE3_TEXT);
            $res = $q->execute();
            $row = $res->fetchArray(SQLITE3_ASSOC);
            $res->finalize();
            $q->close();
            $q = null;

            $db->exec("COMMIT;");
            $in_tx = false;
            if ($row === false) {
                throw new RuntimeException("Counter missing after atomic update: " . $key);
            }
            return intval($row["setting_value"]);
        } catch (Throwable $ex) {
            if ($stmt) {
                $stmt->close();
            }
            if ($q) {
                $q->close();
            }
            if ($in_tx) {
                try { $db->exec("ROLLBACK;"); } catch (Throwable $_rb) {}
            }
            if ($attempt === 4) {
                throw new DbBusyException("Database busy during integer counter increment: " . $key);
            }
            usleep(15000 * ($attempt + 1));
        }
    }
    throw new DbBusyException("Database busy during integer counter increment: " . $key);
}

function get_total_wild_steps($db, $dp_bits) {
    $wild_dps_raw = find_setting_or_null($db, "total_wild_dps");
    $wild_dps = ($wild_dps_raw !== null) ? intval($wild_dps_raw) : 0;
    $legacy_raw = find_setting_or_null($db, "total_wild_steps");
    $legacy_steps = ($legacy_raw !== null) ? floatval($legacy_raw) : 0.0;
    return $legacy_steps + ((float)$wild_dps * pow(2.0, (int)$dp_bits));
}


function parse_incoming_dp_payload() {
    $raw = file_get_contents("php://input");
    if ($raw === false || strlen($raw) < 18) {
        return null;
    }
    $len = strlen($raw);
    if (substr($raw, 0, 4) !== "DPKG") {
        return null;
    }

    $hdr = unpack("nver/nwid_len", substr($raw, 4, 4));
    if (!$hdr || $hdr["ver"] !== 1 || $hdr["wid_len"] < 1 || $hdr["wid_len"] > 128) {
        return null;
    }
    $pos = 8;
    if ($pos + $hdr["wid_len"] + 2 > $len) {
        return null;
    }
    $wid = substr($raw, $pos, $hdr["wid_len"]);
    $pos += $hdr["wid_len"];

    $hw_hdr = unpack("nhw_len", substr($raw, $pos, 2));
    if (!$hw_hdr || $hw_hdr["hw_len"] < 1 || $hw_hdr["hw_len"] > 160) {
        return null;
    }
    $pos += 2;
    if ($pos + $hw_hdr["hw_len"] + 2 > $len) {
        return null;
    }
    $hw = substr($raw, $pos, $hw_hdr["hw_len"]);
    $pos += $hw_hdr["hw_len"];

    $hr_hdr = unpack("nhr_len", substr($raw, $pos, 2));
    if (!$hr_hdr || $hr_hdr["hr_len"] < 1 || $hr_hdr["hr_len"] > 64) {
        return null;
    }
    $pos += 2;
    if ($pos + $hr_hdr["hr_len"] + 4 > $len) {
        return null;
    }
    $hr = substr($raw, $pos, $hr_hdr["hr_len"]);
    $pos += $hr_hdr["hr_len"];

    $cnt_hdr = unpack("Ncount", substr($raw, $pos, 4));
    if (!$cnt_hdr) {
        return null;
    }
    $pos += 4;
    $count = $cnt_hdr["count"];
    if ($count > 10000 || ($pos + ($count * 64)) > $len) {
        return null;
    }

    $dps = [];
    for ($i = 0; $i < $count; ++$i) {
        $bin_x = substr($raw, $pos, 32);
        $pos += 32;
        $bin_dist = substr($raw, $pos, 32);
        $pos += 32;
        $dps[] = [
            "bin_x" => $bin_x,
            "bin_dist" => $bin_dist
        ];
    }

    return [
        "worker_id" => $wid,
        "hardware" => $hw,
        "hashrate" => $hr,
        "dp_list" => $dps
    ];
}

function calculate_hit_probability($total_traps, $wild_steps, $dp_bits, $space_w) {
    if ($dp_bits < 1 || $space_w <= 0.0) {
        throw new InvalidArgumentException("Invalid probability parameters");
    }
    $dp_step = pow(2.0, (int)$dp_bits);
    $tame_steps = (float)$total_traps * $dp_step;

    if ($wild_steps <= 0.0) {
        return [
            "mode" => "TAME_ONLY",
            "prob_numeric" => 0.0,
            "prob_scientific" => "0.000e+00",
            "prob_percent" => "0.000000000000%",
            "odds_text" => "Chưa thả Wild (Đang rải bẫy Tame)",
            "tame_steps_scientific" => sprintf("%.2e", $tame_steps),
            "wild_steps_scientific" => "0"
        ];
    }

    $exponent = (0.75 * $tame_steps * (float)$wild_steps) / (float)$space_w;
    $prob = 1.0 - exp(-$exponent);
    return [
        "mode" => "WILD_ACTIVE",
        "prob_numeric" => $prob,
        "prob_scientific" => sprintf("%.3e", $prob),
        "prob_percent" => sprintf("%.12f%%", $prob * 100.0),
        "odds_text" => ($prob > 0.0) ? ("1 in " . sprintf("%.2e", 1.0 / $prob)) : "N/A",
        "tame_steps_scientific" => sprintf("%.2e", $tame_steps),
        "wild_steps_scientific" => sprintf("%.2e", (float)$wild_steps)
    ];
}

function query_active_workers($db) {
    $now_ts = time();
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $res = null;
        try {
            $workers_list = [];
            $total_hashrate_mhs = 0.0;
            $online_count = 0;
            $res = $db->query("SELECT * FROM active_workers ORDER BY last_seen DESC LIMIT 50;");
            while ($w = $res->fetchArray(SQLITE3_ASSOC)) {
                $last_ts = strtotime($w["last_seen"] . " UTC");
                $diff_sec = max(0, $now_ts - $last_ts);
                $is_online = ($diff_sec <= 120);
                $w["is_online"] = $is_online;
                $w["diff_sec"] = $diff_sec;
                if ($is_online) {
                    $online_count++;
                    if (preg_match("/([\d\.]+)/", $w["hashrate"], $m)) {
                        $total_hashrate_mhs += floatval($m[1]);
                    }
                }
                $workers_list[] = $w;
            }
            $res->finalize();
            return [$workers_list, $online_count, $total_hashrate_mhs];
        } catch (Throwable $ex) {
            if ($res) {
                $res->finalize();
            }
            if ($attempt === 4) {
                throw new DbBusyException("Database busy while querying workers");
            }
            usleep(15000 * ($attempt + 1));
        }
    }
    throw new DbBusyException("Database busy while querying workers");
}

function calculate_database_size_mb($db_path, $shards_dir) {
    $total_bytes = 0;
    if (is_file($db_path)) {
        $sz = @filesize($db_path);
        if ($sz !== false) {
            $total_bytes += $sz;
        }
    }
    $shard_files = @glob($shards_dir . "/traps_*.db*");
    if (is_array($shard_files)) {
        foreach ($shard_files as $sf) {
            if (is_file($sf)) {
                $sz = @filesize($sf);
                if ($sz !== false) {
                    $total_bytes += $sz;
                }
            }
        }
    }
    return round($total_bytes / (1024 * 1024), 2);
}

try {
    $action = isset($_GET["action"]) ? (string)$_GET["action"] : "";
    $is_verify_mode = ((isset($_GET["verify_mode"]) && $_GET["verify_mode"] === "1") || $action === "verify");

    if ($is_verify_mode) {
        if (!in_array($action, ["verify", "get_task", "submit_tame", "check_wild"], true)) {
            http_response_code(400);
            header("Content-Type: application/json");
            echo json_encode(["status" => "ERROR", "message" => "Unsupported action on ephemeral verify.db"]);
            exit;
        }
        $instance_clean = "verify";
    } else {
        $env_instance = getenv("INSTANCE_ID");
        if ($env_instance !== false && $env_instance !== "") {
            $instance_clean = $env_instance;
        } elseif (isset($_GET["instance"]) && $_GET["instance"] !== "") {
            $instance_clean = (string)$_GET["instance"];
        } else {
            $instance_clean = "puzzle140";
        }

        if (!preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $instance_clean) || $instance_clean === "verify") {
            http_response_code(400);
            header("Content-Type: application/json");
            echo json_encode(["status" => "ERROR", "message" => "Invalid instance identifier"]);
            exit;
        }
    }

    $custom_data_root = getenv("KANGAROO_DATA_DIR");
    $base_data_dir = ($custom_data_root !== false && trim($custom_data_root) !== "")
        ? rtrim(trim($custom_data_root), "/")
        : (__DIR__ . "/data");
    protect_storage_dir($base_data_dir);

    // Historical Bitcoin Puzzle Task Vectors (Range & Public Key dispatched to workers during --verify)
    $VERIFY_PUZZLES = [
        1 => ["bits" => 1, "min" => "0x1", "max" => "0x1", "pub" => "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],
        2 => ["bits" => 2, "min" => "0x2", "max" => "0x3", "pub" => "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"],
        3 => ["bits" => 3, "min" => "0x4", "max" => "0x7", "pub" => "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"],
        4 => ["bits" => 4, "min" => "0x8", "max" => "0xf", "pub" => "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"],
        5 => ["bits" => 5, "min" => "0x10", "max" => "0x1f", "pub" => "022b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c"],
        6 => ["bits" => 6, "min" => "0x20", "max" => "0x3f", "pub" => "02f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247"],
        7 => ["bits" => 7, "min" => "0x40", "max" => "0x7f", "pub" => "02497c83c39c76e56d070fb906bced44099de2d0e222575f22e4749682de46eeac"],
        8 => ["bits" => 8, "min" => "0x80", "max" => "0xff", "pub" => "02cea8d97ae24caebb2bba4eff99c743dccac732be31e1b61434d667b8fad96201"],
        9 => ["bits" => 9, "min" => "0x100", "max" => "0x1ff", "pub" => "02e5d533d0b1a50075ead13c9dc41a0ced9a7a2aa2b9c707eab739ff14eece9be5"],
        10 => ["bits" => 10, "min" => "0x200", "max" => "0x3ff", "pub" => "023ee974a28918c2160a9624801f18bf9a87d6a62783323e3cbf138bf43f2192a4"],
        11 => ["bits" => 11, "min" => "0x400", "max" => "0x7ff", "pub" => "02ffabca3b764a327a750bbb2ba1cb8329d43ec0b7dcd8f72855a9d30cf3020f54"],
        12 => ["bits" => 12, "min" => "0x800", "max" => "0xfff", "pub" => "0397793072899a65e5fc4492212329168f4a54fa26b0c4550e15ad7d0226d8509f"],
        13 => ["bits" => 13, "min" => "0x1000", "max" => "0x1fff", "pub" => "0367c20e869ae55d227911be17981d0af9cea7efeec164c05c8e8b85b61d61bf9e"],
        14 => ["bits" => 14, "min" => "0x2000", "max" => "0x3fff", "pub" => "028117d4fd551c9ae74c9fdac45d87bb669bc7dc354b08de037c4a13780734653b"],
        15 => ["bits" => 15, "min" => "0x4000", "max" => "0x7fff", "pub" => "02261bca3e2a7c2c82e525494354a59108e39eaa7fd08a177c295d8a366314146e"],
        16 => ["bits" => 16, "min" => "0x8000", "max" => "0xffff", "pub" => "029dd84f27df2e2cc525c9a79d670722ae3d0e01858ce1f1d7551b9ed470b581b3"],
        17 => ["bits" => 17, "min" => "0x10000", "max" => "0x1ffff", "pub" => "036fe572edaabc2194760b79c4eeffa42cef7b9cae47683a06109bf087ea33b21c"],
        18 => ["bits" => 18, "min" => "0x20000", "max" => "0x3ffff", "pub" => "03068770e25d9777cf3b83f29d2c8375d28b995183000f58f3e6005f0216e2d1b9"],
        19 => ["bits" => 19, "min" => "0x40000", "max" => "0x7ffff", "pub" => "036890f6d6ac6eb70f13d65671072c26acf2e5ff4470965490a24685bde04fe3f0"],
        20 => ["bits" => 20, "min" => "0x80000", "max" => "0xc0000", "pub" => "0214d79b8da08f9e974625f5c6d6bb44e1b177a3f0c0081335b8ec7a6008a6bdd7"],
        21 => ["bits" => 21, "min" => "0x10f1c3", "max" => "0x14f1c3", "pub" => "0245e3c2cea92189322a9983666850e12995029989d144307b76fe4911f5fc85e4"],
        22 => ["bits" => 22, "min" => "0x2efb1e", "max" => "0x32fb1e", "pub" => "02e9bf1601428534d4fb5e0e1dd648d7dcf9c89476d3e1796f05b9f7782375edb4"],
        23 => ["bits" => 23, "min" => "0x73edf3", "max" => "0x77edf3", "pub" => "03a803c681bfef7efc3ba0e9448a4963408c642b0bdefc265af7891651350112f7"],
        24 => ["bits" => 24, "min" => "0x96afa9", "max" => "0x9aafa9", "pub" => "039206d4b5faa2b8773aabbd05818a15a13aa7eb20ebf07e6676f4a2f7cae38f35"],
        25 => ["bits" => 25, "min" => "0x18cf824", "max" => "0x190f824", "pub" => "028b0191fdee249ae5e040a957fe710100de22e58fa00c1da45c34ec3b7080ae98"],
        26 => ["bits" => 26, "min" => "0x22cfdee", "max" => "0x230fdee", "pub" => "0292c3385fbc03f4dfeffc7aaef6a342dc1eb762b30563b607d71d40cafdcdef80"],
        27 => ["bits" => 27, "min" => "0x4ef2913", "max" => "0x4f32913", "pub" => "02c5180d9bd99c3bf5728931bcef733bf13a8635739d4df0923bf1105398673990"],
        28 => ["bits" => 28, "min" => "0x957f392", "max" => "0x95bf392", "pub" => "02e4116fdffe090dd1a3df2dc491acf51ed461487ef7d14b19a0040d18e24dffe7"],
        29 => ["bits" => 29, "min" => "0x15bccd0b", "max" => "0x15c0cd0b", "pub" => "03cf54b8940addeee711aee95f83d001d2bbfb33c8ad33f59c803cda7799fac94d"],
        30 => ["bits" => 30, "min" => "0x2471dd4f", "max" => "0x2475dd4f", "pub" => "032244cbcd2812c5c175ae16e195cb3f80006ec4776c36b128f4511e0fb2d701ca"],
        31 => ["bits" => 31, "min" => "0x5357262d", "max" => "0x535b262d", "pub" => "03e84ae7d43a1d5f921c43f64c2bd53064fb1b009715327366ad8fbaae79643136"],
        32 => ["bits" => 32, "min" => "0x82f1336f", "max" => "0x82f5336f", "pub" => "02ebebe37513c6a17387146b28bf630ead6a95a07f6d509df621d36763fc97f1f1"],
        33 => ["bits" => 33, "min" => "0x1d2265acc", "max" => "0x1d22a5acc", "pub" => "0349425b1b4859e3e88face6d3c80ba65f733e2e03b84c3dacf0ee87f14e8f4bb4"],
        34 => ["bits" => 34, "min" => "0x35e065f2e", "max" => "0x35e0a5f2e", "pub" => "031002176a2c3c9cd8ac9d19f0f163dc814703b4bb98bb10a8302cfce8fa5104a6"],
        35 => ["bits" => 35, "min" => "0x5b31d8ce9", "max" => "0x5b3218ce9", "pub" => "02a5b7321b12a4ae1b84a9c331668052954114aacb4d088382dcb89a0725589c19"],
        36 => ["bits" => 36, "min" => "0xbab024454", "max" => "0xbab064454", "pub" => "0263244c3b892c6437bed2399cba0fe074b3d0f928cf5883bd88d439690d790e80"],
        37 => ["bits" => 37, "min" => "0x17577432f9", "max" => "0x17577832f9", "pub" => "027d2c03c3ef0aec70f2c7e1e75454a5dfdd0e1adea670c1b3a4643c48ad0f1255"],
        38 => ["bits" => 38, "min" => "0x22382dd1cd", "max" => "0x223831d1cd", "pub" => "03c060e1e3771cbeccb38e119c2414702f3f5181a89652538851d2e3886bdd70c6"],
        39 => ["bits" => 39, "min" => "0x4b5f804f85", "max" => "0x4b5f844f85", "pub" => "022d77cd1467019a6bf28f7375d0949ce30e6b5815c2758b98a74c2700bc006543"],
        40 => ["bits" => 40, "min" => "0xe9ae489564", "max" => "0xe9ae4c9564", "pub" => "03a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4"],
        41 => ["bits" => 41, "min" => "0x15386991b8f", "max" => "0x153869d1b8f", "pub" => "03b357e68437da273dcf995a474a524439faad86fc9effc300183f714b0903468b"],
        42 => ["bits" => 42, "min" => "0x2a221c2d77c", "max" => "0x2a221c6d77c", "pub" => "03eec88385be9da803a0d6579798d977a5d0c7f80917dab49cb73c9e3927142cb6"],
        43 => ["bits" => 43, "min" => "0x6bd3b261502", "max" => "0x6bd3b2a1502", "pub" => "02a631f9ba0f28511614904df80d7f97a4f43f02249c8909dac92276ccf0bcdaed"],
        44 => ["bits" => 44, "min" => "0x98d41ce2bb0", "max" => "0x98d41d22bb0", "pub" => "02067f4458a634fa16654bd3a2942bd0723e87914c909916c91303592eda523034"],
        45 => ["bits" => 45, "min" => "0x186c8f931418", "max" => "0x186c8f971418", "pub" => "029823fb02ad69fca8cf6667c2a5f099494e41d6bc8cf432f3476cd1118577b92b"],
        46 => ["bits" => 46, "min" => "0x248554286a43", "max" => "0x2485542c6a43", "pub" => "03c5e754951f498dea6effd25d9c7be419959b6400bee54f6963dd28ba552a8451"],
        47 => ["bits" => 47, "min" => "0x5ec598f70e51", "max" => "0x5ec598fb0e51", "pub" => "03bfe1fc01bf9b2669dacc2e3ee3a14d50c370939fea6c53208368b001abcd1dd2"],
        48 => ["bits" => 48, "min" => "0x91893c7fbdd9", "max" => "0x91893c83bdd9", "pub" => "0257aa20950f54381464d6525a8a1ed925b1878f94ae93296400b15c5d02aec502"],
        49 => ["bits" => 49, "min" => "0x10f135b9ecada", "max" => "0x10f135ba2cada", "pub" => "039ed8fad048a0678b1af5772cfc5281ba0c5303857ee31e0f78cf9ce4c9efd196"],
        50 => ["bits" => 50, "min" => "0x367f0f637efb1", "max" => "0x367f0f63befb1", "pub" => "021bc6c10fa1ef9cdf1b44930479cee11f00fe49e3d3946ded4920a58e74d2dca0"],
        51 => ["bits" => 51, "min" => "0x4ecf8df1d2dea", "max" => "0x4ecf8df212dea", "pub" => "03084570b5eb4b5332f28b9a0695aef694701738509391c65d1d85b3cf4fbd30c9"],
        52 => ["bits" => 52, "min" => "0x8d51fa0d39a29", "max" => "0x8d51fa0d79a29", "pub" => "02e39b170b44fa6b986e968c999123af23736adece4d2b7059b2763952308d3a71"],
        53 => ["bits" => 53, "min" => "0x19942a1978b8a2", "max" => "0x19942a197cb8a2", "pub" => "0364eaf2096c4f6ee8c9f006cc8d5eeb505f613e2536174b2480ba7f51d4a19939"],
        54 => ["bits" => 54, "min" => "0x3e1858a2d5957b", "max" => "0x3e1858a2d9957b", "pub" => "031cd7bd7e86571d586a9f4c11c1d159fc7855c095a517d9b03e1cd95234ca7c60"],
        55 => ["bits" => 55, "min" => "0x4b7b3eebe7de39", "max" => "0x4b7b3eebebde39", "pub" => "03d98297eec59217cf0ad9d878e782ba0f6f7a7711d582fcaf3ded7e947fe57e7b"],
        56 => ["bits" => 56, "min" => "0xb80c804245d894", "max" => "0xb80c804249d894", "pub" => "02e0848f882d14cf6e95e7a0910927109b3881aeae9dde7fd35abb62e4a2cfebe2"],
        57 => ["bits" => 57, "min" => "0x1f3c39601d0141e", "max" => "0x1f3c39601d4141e", "pub" => "0396b44fdc216fc4d954289d99572b39a63466c21c9e00bbdc18dab8d803936271"],
        58 => ["bits" => 58, "min" => "0x3a56cf9e423cde6", "max" => "0x3a56cf9e427cde6", "pub" => "02e1af2d4ab33d2be521ee8fc3a547fd1f3339df7eb76dcb9f599e29f6b073087e"],
        59 => ["bits" => 59, "min" => "0x738356a9bc1b3e8", "max" => "0x738356a9bc5b3e8", "pub" => "02c8a2851cd5dd20b34bb718ef3ac34e2b1682eab00e48f78854fd28724d723f3b"],
        60 => ["bits" => 60, "min" => "0x9e102281a14e276", "max" => "0x9e102281a18e276", "pub" => "03c7aa3bdeaf5c952ee65bc587f8afba33697c8c6cc1e90c64ba53832ab7e7c4e5"],
        61 => ["bits" => 61, "min" => "0x109a7b7389257045", "max" => "0x109a7b7389297045", "pub" => "032d0084f4d1ae62a1f6c562d79ef6378073d2a4cffa393303a7790581f72e3764"],
        62 => ["bits" => 62, "min" => "0x38b3010b991b5f2e", "max" => "0x38b3010b991f5f2e", "pub" => "034b3d0498ab02704f7cfa5ed4141471626d45aad542d9037ab0f221121929d559"],
        63 => ["bits" => 63, "min" => "0x78a487922d96d02f", "max" => "0x78a487922d9ad02f", "pub" => "02379833cb0cc1077173a7fac48c463d3b4b2bca4eb66a6d12a16779d49da75b98"],
        64 => ["bits" => 64, "min" => "0x9d4b66cad1b1fcad", "max" => "0x9d4b66cad1b5fcad", "pub" => "02a48be8fd5b64235965de5d4127b7c04d091daeddf3850db58a1c542c72d5266b"],
        65 => ["bits" => 65, "min" => "0x1a838b13505af2edb", "max" => "0x1a838b13505b32edb", "pub" => "0230210c23b1a047bc9bdbb13448e67deddc108946de6de639bcc75d47c0216b1b"],
        66 => ["bits" => 66, "min" => "0x2832ed74f2b5d959d", "max" => "0x2832ed74f2b61959d", "pub" => "024ee2be2d4e9f92d2f5a4a03058617dc45befe22938feed5b7a6b7282dd74cbdd"],
        67 => ["bits" => 67, "min" => "0x730fc235c193f7c3f", "max" => "0x730fc235c19437c3f", "pub" => "0212209f5ec514a1580a2937bd833979d933199fc230e204c6cdc58872b7d46f75"],
        68 => ["bits" => 68, "min" => "0xbebb3940cd0f94008", "max" => "0xbebb3940cd0fd4008", "pub" => "031fe02f1d740637a7127cdfe8a77a8a0cfc6435f85e7ec3282cb6243c0a93ba1b"],
        69 => ["bits" => 69, "min" => "0x101d83275fb2b8fede", "max" => "0x101d83275fb2bcfede", "pub" => "024babadccc6cfd5f0e5e7fd2a50aa7d677ce0aa16fdce26a0d0882eed03e7ba53"],
        70 => ["bits" => 70, "min" => "0x349b84b6431a69819f", "max" => "0x349b84b6431a6d819f", "pub" => "0290e6900a58d33393bc1097b5aed31f2e4e7cbd3e5466af958665bc0121248483"],
        75 => ["bits" => 75, "min" => "0x4c5ce114686a1311959", "max" => "0x4c5ce114686a1351959", "pub" => "03726b574f193e374686d8e12bc6e4142adeb06770e0a2856f5e4ad89f66044755"],
        80 => ["bits" => 80, "min" => "0xea1a5c66dcc11b59d570", "max" => "0xea1a5c66dcc11b5dd570", "pub" => "037e1238f7b1ce757df94faa9a2eb261bf0aeb9f84dbf81212104e78931c2a19dc"],
        85 => ["bits" => 85, "min" => "0x11720c4f018d51b8cd0e5e", "max" => "0x11720c4f018d51b8d10e5e", "pub" => "0329c4574a4fd8c810b7e42a4b398882b381bcd85e40c6883712912d167c83e73a"],
        90 => ["bits" => 90, "min" => "0x2ce00bb2136a445c71c738e", "max" => "0x2ce00bb2136a445c720738e", "pub" => "035c38bd9ae4b10e8a250857006f3cfd98ab15a6196d9f4dfd25bc7ecc77d788d5"],
        95 => ["bits" => 95, "min" => "0x527a792b183c7f64a0e62801", "max" => "0x527a792b183c7f64a0ea2801", "pub" => "02967a5905d6f3b420959a02789f96ab4c3223a2c4d2762f817b7895c5bc88a045"],
        100 => ["bits" => 100, "min" => "0xaf55fc59c335c8ec67ed15d53", "max" => "0xaf55fc59c335c8ec67ed55d53", "pub" => "03d2063d40402f030d4cc71331468827aa41a8a09bd6fd801ba77fb64f8e67e617"],
        105 => ["bits" => 105, "min" => "0x16f14fc2054cd87ee6396afdcbc", "max" => "0x16f14fc2054cd87ee6396b3dcbc", "pub" => "03bcf7ce887ffca5e62c9cabbdb7ffa71dc183c52c04ff4ee5ee82e0c55c39d77b"],
        110 => ["bits" => 110, "min" => "0x35c0d7234df7deb0f20cf7055f4f", "max" => "0x35c0d7234df7deb0f20cf7095f4f", "pub" => "0309976ba5570966bf889196b7fdf5a0f9a1e9ab340556ec29f8bb60599616167d"],
        115 => ["bits" => 115, "min" => "0x60f4d11574f5deee49961d95eebdb", "max" => "0x60f4d11574f5deee49961d962ebdb", "pub" => "0248d313b0398d4923cdca73b8cfa6532b91b96703902fc8b32fd438a3b7cd7f55"],
        120 => ["bits" => 120, "min" => "0xb10f22572c497a836ea187f2df2e5a", "max" => "0xb10f22572c497a836ea187f2e32e5a", "pub" => "02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630"],
        125 => ["bits" => 125, "min" => "0x1c533b6bb7f0804e09960225e446ca76", "max" => "0x1c533b6bb7f0804e09960225e44aca76", "pub" => "0233709eb11e0d4439a729f21c2c443dedb727528229713f0065721ba8fa46f00e"],
        130 => ["bits" => 130, "min" => "0x33e7665705359f04f28b88cf897c503cd", "max" => "0x33e7665705359f04f28b88cf897c903cd", "pub" => "03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852"],
        135 => ["bits" => 135, "min" => "0x6d9392a16883f90903d5f78da57aefe0ae", "max" => "0x6d9392a16883f90903d5f78da57af3e0ae", "pub" => "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"]
    ];

    // Dedicated Server-Only Historical Private Key Array for --verify Comparison (Never transmitted or printed)
    $VERIFY_EXPECTED_KEYS = [
        1 => "0x1",
        2 => "0x3",
        3 => "0x7",
        4 => "0x8",
        5 => "0x13",
        6 => "0x35",
        7 => "0x56",
        8 => "0xda",
        9 => "0x1da",
        10 => "0x3bf",
        11 => "0x485",
        12 => "0xb48",
        13 => "0x12d6",
        14 => "0x3233",
        15 => "0x6e96",
        16 => "0xa32f",
        17 => "0x1ebd2",
        18 => "0x38d4c",
        19 => "0x738b9",
        20 => "0x98327",
        21 => "0x117466",
        22 => "0x316ba9",
        23 => "0x76884b",
        24 => "0x995dae",
        25 => "0x18e8d53",
        26 => "0x22ee9b5",
        27 => "0x4f26019",
        28 => "0x9599557",
        29 => "0x15bf29f9",
        30 => "0x24749666",
        31 => "0x53580aa6",
        32 => "0x82f2495b",
        33 => "0x1d227914e",
        34 => "0x35e076610",
        35 => "0x5b31fba82",
        36 => "0xbab042e8f",
        37 => "0x1757756a93",
        38 => "0x22382facd0",
        39 => "0x4b5f8303e9",
        40 => "0xe9ae4933d6",
        41 => "0x153869acc5b",
        42 => "0x2a221c58d8f",
        43 => "0x6bd3b27c591",
        44 => "0x98d41cf83bd",
        45 => "0x186c8f95ca04",
        46 => "0x2485542b6623",
        47 => "0x5ec598f80993",
        48 => "0x91893c8340d8",
        49 => "0x10f135b9f91a6",
        50 => "0x367f0f63b655f",
        51 => "0x4ecf8df204859",
        52 => "0x8d51fa0d4c9d3",
        53 => "0x19942a1979b940",
        54 => "0x3e1858a2d75a64",
        55 => "0x4b7b3eebe8b9c6",
        56 => "0xb80c8042466bc5",
        57 => "0x1f3c39601d29319",
        58 => "0x3a56cf9e4266158",
        59 => "0x738356a9bc25557",
        60 => "0x9e102281a17fa2b",
        61 => "0x109a7b7389274945",
        62 => "0x38b3010b991e4a64",
        63 => "0x78a487922d99edbe",
        64 => "0x9d4b66cad1b417e2",
        65 => "0x1a838b13505b26867",
        66 => "0x2832ed74f2b5e35ee",
        67 => "0x730fc235c1942c1ae",
        68 => "0xbebb3940cd0fc1491",
        69 => "0x101d83275fb2bc7e0c",
        70 => "0x349b84b6431a6c4ef1",
        75 => "0x4c5ce114686a1336e07",
        80 => "0xea1a5c66dcc11b5ad180",
        85 => "0x11720c4f018d51b8cebba8",
        90 => "0x2ce00bb2136a445c71e85bf",
        95 => "0x527a792b183c7f64a0e8b1f4",
        100 => "0xaf55fc59c335c8ec67ed24826",
        105 => "0x16f14fc2054cd87ee6396b33df3",
        110 => "0x35c0d7234df7deb0f20cf7062444",
        115 => "0x60f4d11574f5deee49961d9609ac6",
        120 => "0xb10f22572c497a836ea187f2e1fc23",
        125 => "0x1c533b6bb7f0804e09960225e44877ac",
        130 => "0x33e7665705359f04f28b88cf897c603c9",
        135 => "0x6d9392a16883f90903d5f78da57af07eb2"
    ];

    // API: EPHEMERAL verify.db LIFECYCLE (Purges verify.db before & after run; zero orphan directories/shards)
    if ($action === "verify") {
        header("Content-Type: application/json");

        if (isset($_GET["cleanup"]) && $_GET["cleanup"] === "1") {
            purge_verify_db($base_data_dir);
            echo json_encode(["status" => "OK", "deleted" => "verify.db"]);
            exit;
        }

        if (!isset($_GET["init_id"])) {
            purge_verify_db($base_data_dir);
            $catalog = [];
            foreach ($VERIFY_PUZZLES as $pid => $vec) {
                $catalog[] = [
                    "id" => $pid,
                    "bits" => $vec["bits"]
                ];
            }
            echo json_encode([
                "status" => "OK",
                "db_file" => "verify.db",
                "total" => count($catalog),
                "puzzles" => $catalog
            ]);
            exit;
        }
    }

    if ($is_verify_mode) {
        $db_path = $base_data_dir . "/verify.db";
        $vault_path = "";
        $shards_dir = "";
    } else {
        $data_dir = $base_data_dir . "/" . $instance_clean;
        protect_storage_dir($data_dir);
        $db_path = $data_dir . "/system_" . $instance_clean . ".db";
        $vault_path = $data_dir . "/bingo_key.php";
        $shards_dir = $data_dir . "/shards";
        protect_storage_dir($shards_dir);
    }

    $db_existed = file_exists($db_path);
    $db = new SQLite3($db_path);
    $db->enableExceptions(true);
    $db->busyTimeout(30000);
    if (!$db_existed) {
        if (!chmod($db_path, 0600)) {
            throw new RuntimeException("Failed to secure primary database permissions");
        }
    }
    $db->exec("PRAGMA journal_mode = WAL;");
    $db->exec("PRAGMA synchronous = NORMAL;");
    $db->exec("PRAGMA wal_autocheckpoint = 1000;");
    $db->exec("PRAGMA cache_size = " . ($is_verify_mode ? "-4096" : "-131072") . ";");
    $db->exec("PRAGMA mmap_size = " . ($is_verify_mode ? "33554432" : "536870912") . ";");
    $db->exec("PRAGMA temp_store = MEMORY;");

    $db->exec("
        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_workers (
            worker_id TEXT PRIMARY KEY,
            hardware TEXT NOT NULL,
            hashrate TEXT NOT NULL,
            mode TEXT NOT NULL,
            total_dps INTEGER NOT NULL DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ");

    if ($is_verify_mode) {
        $db->exec("CREATE TABLE IF NOT EXISTS tame_traps (
            dp_x BLOB PRIMARY KEY,
            total_distance BLOB NOT NULL
        ) WITHOUT ROWID;");
        $active_shard_count = 1;
        $active_shard_mask = 0;
    } else {
        $db->exec("
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('target_dp', '50000000');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('range_min', '0x80000000000000000000000000000000000');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('range_max', '0xfffffffffffffffffffffffffffffffffff');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('target_pubkey', '031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('dp_mask_bits', '23');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('batch_limit', '1000');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('heartbeat_sec', '30');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('total_wild_dps', '0');
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('total_tame_traps', '0');
        ");
        $stored_shards = find_setting_or_null($db, "shard_count");
        if ($stored_shards === null) {
            $existing_traps_raw = find_setting_or_null($db, "total_tame_traps");
            $existing_traps = ($existing_traps_raw !== null) ? intval($existing_traps_raw) : 0;
            $legacy_high = ($existing_traps > 0) ? glob($shards_dir . "/traps_[2-9a-f][0-9a-f].db") : [];
            $active_shard_count = (!empty($legacy_high)) ? 256 : DEFAULT_SHARD_COUNT;
            set_setting($db, "shard_count", (string)$active_shard_count);
        } else {
            $parsed_sc = intval($stored_shards);
            if ($parsed_sc !== 32 && $parsed_sc !== 256) {
                throw new RuntimeException("Unsupported shard_count setting: " . $stored_shards);
            }
            $active_shard_count = $parsed_sc;
        }
        $active_shard_mask = $active_shard_count - 1;
    }

    if ($action === "verify" && isset($_GET["init_id"])) {
        header("Content-Type: application/json");
        $pid = intval($_GET["init_id"]);
        if (!isset($VERIFY_PUZZLES[$pid])) {
            $db->close();
            http_response_code(404);
            echo json_encode(["status" => "ERROR", "message" => "Unknown historical puzzle id"]);
            exit;
        }

        $db->exec("BEGIN IMMEDIATE TRANSACTION;");
        $db->exec("DELETE FROM tame_traps;");
        $db->exec("DELETE FROM active_workers;");
        $db->exec("DELETE FROM system_settings WHERE setting_key IN ('verify_solved', 'verify_puzzle_id', 'total_wild_steps');");
        $db->exec("COMMIT;");

        $vec = $VERIFY_PUZZLES[$pid];
        list($w_u, $_) = u256_sub(u256_from_hex($vec["max"]), u256_from_hex($vec["min"]));
        if (u256_cmp($w_u, u256_from_int(4095)) <= 0) {
            $v_dp_bits = 4;
            $v_target_dp = 24;
            $v_batch = 24;
        } else {
            $v_dp_bits = 5;
            $v_target_dp = 64;
            $v_batch = 64;
        }

        set_setting($db, "verify_puzzle_id", (string)$pid);
        set_setting($db, "range_min", $vec["min"]);
        set_setting($db, "range_max", $vec["max"]);
        set_setting($db, "target_pubkey", $vec["pub"]);
        set_setting($db, "dp_mask_bits", (string)$v_dp_bits);
        set_setting($db, "target_dp", (string)$v_target_dp);
        set_setting($db, "batch_limit", (string)$v_batch);
        set_setting($db, "heartbeat_sec", "1");
        set_setting($db, "total_tame_traps", "0");
        set_setting($db, "total_wild_dps", "0");
        $db->close();

        echo json_encode([
            "status" => "OK",
            "id" => $pid,
            "bits" => $vec["bits"],
            "dp_mask_bits" => $v_dp_bits,
            "target_dp" => $v_target_dp
        ]);
        exit;
    }


    // API 1: GET TASK
    if ($action === "get_task") {
        header("Content-Type: application/json");
        $tame_count = intval(get_required_setting($db, "total_tame_traps"));
        $target_dp = intval(get_required_setting($db, "target_dp"));
        $batch_lim = intval(get_required_setting($db, "batch_limit"));
        $hb_base = intval(get_required_setting($db, "heartbeat_sec"));
        $r_min = get_required_setting($db, "range_min");
        $r_max = get_required_setting($db, "range_max");
        $t_pub = get_required_setting($db, "target_pubkey");
        $dp_b = intval(get_required_setting($db, "dp_mask_bits"));
        $is_solved = $is_verify_mode
            ? (find_setting_or_null($db, "verify_solved") === "1")
            : file_exists($vault_path);
        $task_type = ($tame_count >= $target_dp) ? "WILD" : "TAME";

        if ($is_verify_mode) {
            $db->close();
        }

        echo json_encode([
            "status" => $is_solved ? "BINGO" : "OK",
            "stop" => $is_solved,
            "task_type" => $task_type,
            "current_traps" => $tame_count,
            "target_traps" => $target_dp,
            "range_min" => $r_min,
            "range_max" => $r_max,
            "target_pubkey" => $t_pub,
            "dp_mask_bits" => $dp_b,
            "batch_limit" => $batch_lim,
            "heartbeat_sec" => $hb_base
        ]);
        exit;
    }

    // API 2 & 3: SUBMIT TAME & CHECK WILD
    if ($action === "submit_tame" || $action === "check_wild") {
        header("Content-Type: application/json");

        $already_solved = $is_verify_mode
            ? (find_setting_or_null($db, "verify_solved") === "1")
            : file_exists($vault_path);
        if ($already_solved) {
            if ($is_verify_mode) {
                $db->close();
            }
            echo json_encode(["status" => "BINGO", "stop" => true]);
            exit;
        }

        $payload = parse_incoming_dp_payload();
        if ($payload === null) {
            if ($is_verify_mode) {
                $db->close();
            }
            http_response_code(400);
            echo json_encode(["status" => "ERROR", "message" => "Malformed DPKG binary payload"]);
            exit;
        }

        $worker_id = $payload["worker_id"];
        $hardware = $payload["hardware"];
        $hashrate = $payload["hashrate"];
        $dp_list = $payload["dp_list"];
        $batch_size = count($dp_list);
        $current_mode = ($action === "check_wild") ? "WILD" : "TAME";

        // Note: Worker registry and counters are updated atomically in master transaction at end of request

        if ($action === "submit_tame") {
            $shard_groups = [];
            foreach ($dp_list as $dp) {
                $bin_x = $dp["bin_x"];
                $bin_dist = $dp["bin_dist"];
                $shard_idx = ord($bin_x[31]) & $active_shard_mask;
                $packed_dist = ltrim($bin_dist, "\0");
                if ($packed_dist === "") {
                    $packed_dist = "\0";
                }
                $shard_groups[$shard_idx][] = ["x" => $bin_x, "dist" => $packed_dist];
            }

            ksort($shard_groups);
            $actual_inserted = 0;

            foreach ($shard_groups as $shard_idx => $group) {
                $sdb = get_shard_db($shard_idx, true);
                for ($attempt = 0; $attempt < 5; $attempt++) {
                    $in_tx = false;
                    $shard_added = 0;
                    try {
                        $sdb->exec("BEGIN IMMEDIATE TRANSACTION;");
                        $in_tx = true;
                        
                        // TASK 1: Multi-Row Batch INSERT (chunks of 50 items = 100 parameters)
                        $chunks = array_chunk($group, 50);
                        foreach ($chunks as $chunk) {
                            $placeholders = implode(",", array_fill(0, count($chunk), "(?, ?)"));
                            $sins = $sdb->prepare("INSERT OR IGNORE INTO tame_traps (dp_x, total_distance) VALUES " . $placeholders . ";");
                            $param_idx = 1;
                            foreach ($chunk as $item) {
                                $sins->bindValue($param_idx++, $item["x"], SQLITE3_BLOB);
                                $sins->bindValue($param_idx++, $item["dist"], SQLITE3_BLOB);
                            }
                            $sins->execute();
                            $sins->close();
                            $shard_added += $sdb->changes();
                        }
                        
                        $sdb->exec("COMMIT;");
                        $in_tx = false;
                        $actual_inserted += $shard_added;
                        break;
                    } catch (Throwable $ex) {
                        if ($in_tx) {
                            try { $sdb->exec("ROLLBACK;"); } catch (Throwable $_rb) {}
                        }
                        if ($attempt === 4) {
                            if ($actual_inserted > 0) {
                                increment_setting_int($db, "total_tame_traps", $actual_inserted);
                            }
                            throw new DbBusyException("Tame shard " . $shard_idx . " busy");
                        }
                        usleep(20000 * ($attempt + 1));
                    }
                }
            }

            // TASK 2: Throttled Master DB update to eliminate write lock contention
            $w_throttle_file = sys_get_temp_dir() . "/k_hb_" . md5($worker_id . "_" . $instance_clean);
            $now_time = time();
            $should_update_worker = (!file_exists($w_throttle_file) || ($now_time - @filemtime($w_throttle_file) >= 20));

            if ($should_update_worker || $actual_inserted > 0) {
                for ($att = 0; $att < 10; $att++) {
                    $in_m_tx = false;
                    try {
                        $db->exec("BEGIN IMMEDIATE TRANSACTION;");
                        $in_m_tx = true;
                        if ($should_update_worker) {
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
                            $w_stmt->close();
                            @touch($w_throttle_file);
                        }

                        if ($actual_inserted > 0) {
                            $s_stmt = $db->prepare("INSERT INTO system_settings (setting_key, setting_value)
                                                    VALUES ('total_tame_traps', :val)
                                                    ON CONFLICT(setting_key) DO UPDATE SET
                                                        setting_value = CAST(setting_value AS INTEGER) + :val;");
                            $s_stmt->bindValue(":val", $actual_inserted, SQLITE3_INTEGER);
                            $s_stmt->execute();
                            $s_stmt->close();
                        }

                        $db->exec("COMMIT;");
                        $in_m_tx = false;
                        break;
                    } catch (Throwable $ex) {
                        if ($in_m_tx) {
                            try { $db->exec("ROLLBACK;"); } catch (Throwable $_rb) {}
                        }
                        if ($att === 9) {
                            throw new DbBusyException("Master DB busy during tame atomic commit");
                        }
                        usleep((10000 + mt_rand(5000, 25000)) * ($att + 1));
                    }
                }
            }
            $total_raw = find_setting_or_null($db, "total_tame_traps");
            $total = ($total_raw !== null) ? intval($total_raw) : 0;
            $target_dp = intval(get_required_setting($db, "target_dp"));
            $dp_bits = intval(get_required_setting($db, "dp_mask_bits"));
            $space_w = get_space_width_float(get_required_setting($db, "range_min"), get_required_setting($db, "range_max"));
            $task_type = ($total >= $target_dp) ? "WILD" : "TAME";
            $prob_info = calculate_hit_probability($total, 0.0, $dp_bits, $space_w);

            if ($is_verify_mode) {
                $db->close();
            }
            echo json_encode([
                "status" => "OK",
                "accepted" => $actual_inserted,
                "received" => $batch_size,
                "total_traps" => $total,
                "task_type" => $task_type,
                "probability" => $prob_info["prob_scientific"]
            ]);
            exit;
        }

        if ($action === "check_wild") {
            $range_min = get_required_setting($db, "range_min");
            $range_max = get_required_setting($db, "range_max");
            $target_pubkey = get_required_setting($db, "target_pubkey");

            $shard_groups = [];
            foreach ($dp_list as $dp) {
                $shard_idx = ord($dp["bin_x"][31]) & $active_shard_mask;
                $shard_groups[$shard_idx][] = $dp;
            }
            ksort($shard_groups);

            foreach ($shard_groups as $shard_idx => $group) {
                $sdb = get_shard_db($shard_idx, false);
                if ($sdb === null) {
                    continue;
                }

                $in_read_tx = false;
                if (!$is_verify_mode) {
                    for ($tx_att = 0; $tx_att < 5; $tx_att++) {
                        try {
                            $sdb->exec("BEGIN DEFERRED TRANSACTION;");
                            $in_read_tx = true;
                            break;
                        } catch (Throwable $ex) {
                            if ($tx_att === 4) {
                                throw new DbBusyException("Wild read snapshot busy on shard " . $shard_idx);
                            }
                            usleep(15000 * ($tx_att + 1));
                        }
                    }
                }

                $chunks = array_chunk($group, 50);
                foreach ($chunks as $chunk) {
                    $placeholders = implode(",", array_fill(0, count($chunk), "?"));
                    $schk = null;
                    for ($prep_att = 0; $prep_att < 5; $prep_att++) {
                        try {
                            $schk = $sdb->prepare("SELECT dp_x, total_distance FROM tame_traps WHERE dp_x IN ($placeholders);");
                            break;
                        } catch (Throwable $ex) {
                            if ($prep_att === 4) {
                                if ($in_read_tx) { try { $sdb->exec("ROLLBACK;"); } catch (Throwable $_rb) {} }
                                throw new DbBusyException("Wild lookup prepare busy on shard " . $shard_idx);
                            }
                            usleep(15000 * ($prep_att + 1));
                        }
                    }

                    $map_by_x = [];
                    foreach ($chunk as $c_idx => $dp_item) {
                        $schk->bindValue($c_idx + 1, $dp_item["bin_x"], SQLITE3_BLOB);
                        $map_by_x[$dp_item["bin_x"]] = $dp_item["bin_dist"];
                    }

                    $sres = null;
                    $matched_rows = [];
                    for ($attempt = 0; $attempt < 5; $attempt++) {
                        try {
                            $sres = $schk->execute();
                            while ($row = $sres->fetchArray(SQLITE3_ASSOC)) {
                                $matched_rows[] = $row;
                            }
                            $sres->finalize();
                            break;
                        } catch (Throwable $ex) {
                            if ($sres) { $sres->finalize(); }
                            if ($attempt === 4) {
                                $schk->close();
                                if ($in_read_tx) { try { $sdb->exec("ROLLBACK;"); } catch (Throwable $_rb) {} }
                                throw new DbBusyException("Wild lookup execution busy on shard " . $shard_idx);
                            }
                            usleep(15000 * ($attempt + 1));
                        }
                    }
                    $schk->close();

                    foreach ($matched_rows as $row) {
                        $bin_x = $row["dp_x"];
                        $bin_dist = $map_by_x[$bin_x];
                        $raw_tame_dist = $row["total_distance"];
                        if (strlen($raw_tame_dist) < 32) {
                            $raw_tame_dist = str_pad($raw_tame_dist, 32, "\0", STR_PAD_LEFT);
                        }
                        $tame_dist_hex = bin2hex($raw_tame_dist);
                        $wild_dist_hex = bin2hex($bin_dist);
                        $cands = solve_candidate_keys($range_min, $range_max, $tame_dist_hex, $wild_dist_hex, $target_pubkey);

                        if (!$cands["is_verified"]) {
                            continue;
                        }

                        if ($in_read_tx) {
                            try { $sdb->exec("COMMIT;"); } catch (Throwable $_cm) {}
                            $in_read_tx = false;
                        }

                        $collision_dp_hex = "0x" . bin2hex($bin_x);
                        $total_traps_now = intval(get_required_setting($db, "total_tame_traps"));

                        if ($batch_size > 0) {
                            increment_setting_int($db, "total_wild_dps", $batch_size);
                        }

                        if ($is_verify_mode) {
                            $active_pid = intval(get_required_setting($db, "verify_puzzle_id"));
                            if (!isset($VERIFY_EXPECTED_KEYS[$active_pid])) {
                                $db->close();
                                throw new RuntimeException("Missing expected verification key for puzzle #" . $active_pid);
                            }
                            $expected_canonical = "0x" . u256_to_hex(u256_from_hex($VERIFY_EXPECTED_KEYS[$active_pid]));
                            $key_matched = hash_equals($expected_canonical, $cands["verified_key"]);
                            if (!$key_matched) {
                                $db->close();
                                http_response_code(500);
                                echo json_encode([
                                    "status" => "ERROR",
                                    "key_matched" => false,
                                    "message" => "Recovered private key mismatch against historical puzzle #" . $active_pid
                                ]);
                                exit;
                            }
                            set_setting($db, "verify_solved", "1");
                            $db->close();
                            echo json_encode([
                                "status" => "BINGO",
                                "stop" => true,
                                "key_matched" => true,
                                "total_traps" => $total_traps_now
                            ]);
                            exit;
                        }

                        $trimmed_priv = ltrim(substr($cands["verified_key"], 2), "0");
                        $compact_priv = "0x" . ($trimmed_priv === "" ? "0" : $trimmed_priv);

                        $vault_data = json_encode([
                            "status" => "BINGO",
                            "instance" => $instance_clean,
                            "timestamp_utc" => gmdate("Y-m-d H:i:s"),
                            "worker_id" => $worker_id,
                            "hardware" => $hardware,
                            "private_key" => $compact_priv,
                            "private_key_padded" => $cands["verified_key"],
                            "derived_pubkey" => $cands["derived_pubkey"],
                            "collision_dp_x" => $collision_dp_hex,
                            "tame_distance" => "0x" . $tame_dist_hex,
                            "wild_distance" => "0x" . $wild_dist_hex
                        ], JSON_PRETTY_PRINT);

                        $vault_file_content = PHP_GUARD . $vault_data . "\n";
                        if (file_put_contents($vault_path, $vault_file_content, LOCK_EX) === false || !chmod($vault_path, 0600)) {
                            throw new DbBusyException("Failed to persist bingo_key.php; worker must retry");
                        }

                        echo json_encode([
                            "status" => "BINGO",
                            "stop" => true
                        ]);
                        exit;
                    }
                }

                if ($in_read_tx) {
                    try { $sdb->exec("COMMIT;"); } catch (Throwable $_cm) {}
                    $in_read_tx = false;
                }
            }

            // TASK 2: Throttled Master DB update to eliminate write lock contention
            $w_throttle_file = sys_get_temp_dir() . "/k_hb_" . md5($worker_id . "_" . $instance_clean);
            $now_time = time();
            $should_update_worker = (!file_exists($w_throttle_file) || ($now_time - @filemtime($w_throttle_file) >= 20));

            if ($should_update_worker) {
                for ($att = 0; $att < 10; $att++) {
                    $in_m_tx = false;
                    try {
                        $db->exec("BEGIN IMMEDIATE TRANSACTION;");
                        $in_m_tx = true;
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
                        $w_stmt->close();

                        if ($batch_size > 0) {
                            $s_stmt = $db->prepare("INSERT INTO system_settings (setting_key, setting_value)
                                                    VALUES ('total_wild_dps', :val)
                                                    ON CONFLICT(setting_key) DO UPDATE SET
                                                        setting_value = CAST(setting_value AS INTEGER) + :val;");
                            $s_stmt->bindValue(":val", $batch_size, SQLITE3_INTEGER);
                            $s_stmt->execute();
                            $s_stmt->close();
                        }

                        $db->exec("COMMIT;");
                        $in_m_tx = false;
                        @touch($w_throttle_file);
                        break;
                    } catch (Throwable $ex) {
                        if ($in_m_tx) {
                            try { $db->exec("ROLLBACK;"); } catch (Throwable $_rb) {}
                        }
                        if ($att === 9) {
                            throw new DbBusyException("Master DB busy during wild atomic commit");
                        }
                        usleep((10000 + mt_rand(5000, 25000)) * ($att + 1));
                    }
                }
            }

            $total_traps = intval(get_required_setting($db, "total_tame_traps"));
            $target_dp = intval(get_required_setting($db, "target_dp"));
            $task_type = ($total_traps >= $target_dp) ? "WILD" : "TAME";

            if ($is_verify_mode) {
                $db->close();
            }

            echo json_encode([
                "status" => "CONTINUE",
                "stop" => false,
                "checked" => $batch_size,
                "task_type" => $task_type
            ]);
            exit;
        }
    }

    // API 4: SET TARGET DP
    if ($action === "set_target_dp") {
        header("Content-Type: application/json");
        $input = file_get_contents("php://input");
        $payload = is_string($input) ? json_decode($input, true) : null;
        if (!is_array($payload)) {
            http_response_code(400);
            echo json_encode(["status" => "ERROR", "message" => "Invalid JSON body"]);
            exit;
        }


        if (!isset($payload["target_dp"]) || intval($payload["target_dp"]) <= 0) {
            http_response_code(400);
            echo json_encode(["status" => "ERROR", "message" => "Invalid target_dp"]);
            exit;
        }

        $val = intval($payload["target_dp"]);
        set_setting($db, "target_dp", (string)$val);
        echo json_encode(["status" => "SUCCESS", "target_dp" => $val]);
        exit;
    }

    // API 5: GET STATS
    if ($action === "get_stats") {
        header("Content-Type: application/json");
        $total_traps = intval(get_required_setting($db, "total_tame_traps"));
        $target_dp = intval(get_required_setting($db, "target_dp"));
        $dp_bits = intval(get_required_setting($db, "dp_mask_bits"));
        $wild_dps_raw = find_setting_or_null($db, "total_wild_dps");
        $total_wild_dps = ($wild_dps_raw !== null) ? intval($wild_dps_raw) : 0;
        $wild_steps = get_total_wild_steps($db, $dp_bits);
        $space_w = get_space_width_float(get_required_setting($db, "range_min"), get_required_setting($db, "range_max"));
        $prob = calculate_hit_probability($total_traps, $wild_steps, $dp_bits, $space_w);

        list($workers_list, $online_count, $total_hashrate_mhs) = query_active_workers($db);
        $db_size_mb = calculate_database_size_mb($db_path, $shards_dir);
        $vault_solved = file_exists($vault_path);

        echo json_encode([
            "instance" => $instance_clean,
            "current_dp" => $total_traps,
            "current_dp_formatted" => number_format($total_traps),
            "target_dp" => $target_dp,
            "target_dp_formatted" => number_format($target_dp),
            "total_wild_dps" => $total_wild_dps,
            "progress_pct" => min(100.0, round(($total_traps / max(1, $target_dp)) * 100.0, 2)),
            "current_phase" => ($total_traps >= $target_dp) ? "WILD" : "TAME",
            "phase_label" => ($total_traps >= $target_dp) ? "WILD HUNT" : "TAME GENERATION",
            "total_hashrate_mhs" => number_format($total_hashrate_mhs, 2),
            "active_workers_count" => $online_count,
            "total_workers_count" => count($workers_list),
            "database_size_mb" => $db_size_mb,
            "winning_probability" => $prob,
            "workers" => $workers_list,
            "vault_solved" => $vault_solved
        ]);
        exit;
    }

    if ($action !== "") {
        http_response_code(400);
        header("Content-Type: application/json");
        echo json_encode(["status" => "ERROR", "message" => "Unknown action"]);
        exit;
    }

    // Web Dashboard (action == "")
    $total_traps = intval(get_required_setting($db, "total_tame_traps"));
    $target_dp = intval(get_required_setting($db, "target_dp"));
    $vault_exists = file_exists($vault_path);
    $db_size_mb = calculate_database_size_mb($db_path, $shards_dir);
    $dp_bits = intval(get_required_setting($db, "dp_mask_bits"));
    $wild_steps = get_total_wild_steps($db, $dp_bits);
    $space_w = get_space_width_float(get_required_setting($db, "range_min"), get_required_setting($db, "range_max"));
    $prob_info = calculate_hit_probability($total_traps, $wild_steps, $dp_bits, $space_w);
    list($workers, $active_workers_count, $total_hashrate_mhs) = query_active_workers($db);
    $progress_pct = min(100.0, round(($total_traps / max(1, $target_dp)) * 100.0, 2));

} catch (DbBusyException $e) {
    http_response_code(503);
    header("Content-Type: application/json");
    echo json_encode(["status" => "BUSY", "message" => $e->getMessage()]);
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    header("Content-Type: application/json");
    echo json_encode(["status" => "ERROR", "message" => $e->getMessage()]);
    exit;
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kangaroo Master Coordinator - <?= htmlspecialchars($instance_clean) ?></title>
    <style>
        * { box-sizing: border-box; }
        body { background: #0b1120; color: #f1f5f9; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; margin: 0; padding: 24px; }
        .container { max-width: 1100px; margin: 0 auto; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 700; }
        .badge-green { background: #065f46; color: #34d399; }
        .badge-amber { background: #78350f; color: #fbbf24; }
        .badge-blue { background: #1e3a8a; color: #60a5fa; }
        .badge-gray { background: #334155; color: #94a3b8; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .stat-val { font-size: 22px; font-weight: 700; color: #38bdf8; margin-top: 6px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid #334155; font-size: 13px; }
        th { color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        .progress-bar-bg { background: #334155; border-radius: 4px; height: 6px; margin: 8px 0; overflow: hidden; }
        .progress-bar-fill { background: #38bdf8; height: 100%; border-radius: 4px; transition: width 0.3s; }
        .pulse-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #34d399; }
        .btn-toggle { background: #334155; border: 1px solid #475569; color: #cbd5e1; font-size: 11px; padding: 3px 8px; border-radius: 4px; cursor: pointer; }
        .btn-toggle:hover { background: #475569; color: #fff; }
    </style>
    <script>
        const INSTANCE_ID = <?= json_encode($instance_clean) ?>;
        let autoRefresh = true;
        let secondsLeft = 10;

        function apiUrl(action) {
            return "?instance=" + encodeURIComponent(INSTANCE_ID) + "&action=" + encodeURIComponent(action);
        }

        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            const btn = document.getElementById("toggle-refresh-btn");
            if (btn) btn.innerText = autoRefresh ? "Tự động: BẬT" : "Tự động: TẮT";
            const timerEl = document.getElementById("countdown");
            if (timerEl && !autoRefresh) timerEl.innerText = "Tạm dừng";
        }

        async function fetchStats() {
            const res = await fetch(apiUrl("get_stats"));
            if (!res.ok) {
                throw new Error("HTTP " + res.status);
            }
            const data = await res.json();

            const elTraps = document.getElementById("val-traps");
            if (elTraps) elTraps.innerText = data.current_dp_formatted;

            const elTarget = document.getElementById("val-target");
            if (elTarget) elTarget.innerText = "/ " + data.target_dp_formatted + " DPs";

            const elProgress = document.getElementById("val-progress");
            if (elProgress) elProgress.innerText = data.progress_pct + "%";

            const elBar = document.getElementById("progress-fill");
            if (elBar) elBar.style.width = data.progress_pct + "%";

            const elPhase = document.getElementById("val-phase");
            if (elPhase) {
                elPhase.innerText = data.phase_label;
                elPhase.style.color = (data.current_phase === "WILD") ? "#34d399" : "#fbbf24";
            }

            const elBadgePhase = document.getElementById("header-phase-badge");
            if (elBadgePhase) {
                if (data.current_phase === "WILD") {
                    elBadgePhase.className = "badge badge-green";
                    elBadgePhase.innerText = "GIAI ĐOẠN 2: WILD HUNTING";
                } else {
                    elBadgePhase.className = "badge badge-amber";
                    elBadgePhase.innerText = "GIAI ĐOẠN 1: TAME TRAPS (" + data.progress_pct + "%)";
                }
            }

            const elVaultBadge = document.getElementById("val-vault-badge");
            if (elVaultBadge) {
                if (data.vault_solved) {
                    elVaultBadge.className = "badge badge-green";
                    elVaultBadge.innerText = "BINGO (bingo_key.php)";
                } else {
                    elVaultBadge.className = "badge badge-amber";
                    elVaultBadge.innerText = "ĐANG SĂN";
                }
            }

            const elBingoBanner = document.getElementById("bingo-banner");
            if (elBingoBanner) {
                elBingoBanner.style.display = data.vault_solved ? "block" : "none";
            }
            if (data.vault_solved && elBadgePhase) {
                elBadgePhase.className = "badge badge-green";
                elBadgePhase.innerText = "BINGO — ĐÃ GIẢI XONG PUZZLE";
            }

            const elHashrate = document.getElementById("val-hashrate");
            if (elHashrate) elHashrate.innerText = data.total_hashrate_mhs;

            const elWorkersCount = document.getElementById("val-workers-count");
            if (elWorkersCount) elWorkersCount.innerText = data.active_workers_count + " Online (" + data.total_workers_count + " tổng)";

            const elProb = document.getElementById("val-prob");
            if (elProb && data.winning_probability) elProb.innerText = data.winning_probability.prob_percent;

            const elOdds = document.getElementById("val-odds");
            if (elOdds && data.winning_probability) elOdds.innerText = data.winning_probability.odds_text;

            const elProbSci = document.getElementById("val-prob-sci");
            if (elProbSci && data.winning_probability) elProbSci.innerText = data.winning_probability.prob_scientific;

            const elDbSize = document.getElementById("val-dbsize");
            if (elDbSize) elDbSize.innerText = data.database_size_mb;

            if (Array.isArray(data.workers)) {
                const tbody = document.getElementById("workers-tbody");
                if (tbody) {
                    if (data.workers.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="7" style="color: #64748b; text-align: center; padding: 16px;">Chưa có worker nào kết nối. Khởi chạy với: <code>bash run.sh</code></td></tr>';
                    } else {
                        let html = "";
                        for (const w of data.workers) {
                            const isOnline = w.is_online;
                            const modeBadge = (w.mode === "WILD") ? "badge-green" : "badge-amber";
                            const statusBadge = isOnline ? "badge-green" : "badge-gray";
                            const statusText = isOnline ? "ONLINE" : "OFFLINE";
                            html += `<tr>
                                <td style="color: #38bdf8; font-weight: 600; font-family: monospace;">${escapeHtml(w.worker_id)}</td>
                                <td>${escapeHtml(w.hardware)}</td>
                                <td style="color: #34d399; font-weight: 600;">${escapeHtml(w.hashrate)}</td>
                                <td><span class="badge ${modeBadge}">${escapeHtml(w.mode)}</span></td>
                                <td>${Number(w.total_dps).toLocaleString()}</td>
                                <td style="color: #94a3b8; font-size: 12px;">${escapeHtml(w.last_seen)}</td>
                                <td><span class="badge ${statusBadge}" style="font-size: 11px;">${statusText}</span></td>
                            </tr>`;
                        }
                        tbody.innerHTML = html;
                    }
                }
            }
        }

        function escapeHtml(str) {
            return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        }

        window.addEventListener("DOMContentLoaded", function() {
        });

        setInterval(function() {
            if (!autoRefresh) return;
            secondsLeft--;
            const timerEl = document.getElementById("countdown");
            if (timerEl) timerEl.innerText = secondsLeft + "s";
            if (secondsLeft <= 0) {
                secondsLeft = 10;
                fetchStats().catch(function(err) {
                    if (timerEl) timerEl.innerText = "Lỗi kết nối";
                    console.error(err);
                });
            }
        }, 1000);
    </script>
</head>
<body>
<div class="container">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 12px;">
        <div>
            <h2 style="margin: 0; color: #38bdf8; font-size: 22px;">Kangaroo Master Coordinator</h2>
            <div style="font-size: 12px; color: #64748b; margin-top: 4px;">
                Pure-PHP 256-Bit Secp256k1 Verifier • Instance: <strong><?= htmlspecialchars($instance_clean) ?></strong>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
            <span id="header-phase-badge" class="badge <?= $vault_exists ? 'badge-green' : (($total_traps < $target_dp) ? 'badge-amber' : 'badge-green') ?>">
                <?= $vault_exists ? 'BINGO — ĐÃ GIẢI XONG PUZZLE' : (($total_traps < $target_dp) ? 'GIAI ĐOẠN 1: TAME TRAPS (' . $progress_pct . '%)' : 'GIAI ĐOẠN 2: WILD HUNTING') ?>
            </span>
            <span class="badge badge-blue">Pure PHP + SQLite WAL</span>
            <button id="toggle-refresh-btn" onclick="toggleAutoRefresh()" class="btn-toggle">Tự động: BẬT</button>
            <span style="font-size: 11px; color: #94a3b8; margin-left: 2px;">Cập nhật trong: <strong id="countdown" style="color: #38bdf8;">10s</strong></span>
        </div>
    </div>

    <div id="bingo-banner" class="card" style="display: <?= $vault_exists ? 'block' : 'none' ?>; background: #064e3b; border-color: #10b981; color: #ecfdf5;">
        <div style="font-size: 16px; font-weight: 700; color: #34d399;">BINGO! ĐÃ TÌM RA PRIVATE KEY PUZZLE</div>
        <div style="font-size: 13px; margin-top: 6px; color: #d1fae5;">
            Private Key đã được xác thực Secp256k1 và lưu bảo mật trên server tại:
            <code style="background: #022c22; padding: 3px 8px; border-radius: 4px; color: #6ee7b7;">data/<?= htmlspecialchars($instance_clean) ?>/bingo_key.php</code>
            — Toàn bộ CPU/GPU Workers đã tự động dừng (không in/truyền key ra worker).
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Tiến Độ Bẫy Tame</div>
            <div class="stat-val"><span id="val-traps"><?= number_format($total_traps) ?></span> <span id="val-target" style="font-size: 13px; font-weight: normal; color: #64748b;">/ <?= number_format($target_dp) ?> DPs</span></div>
            <div class="progress-bar-bg">
                <div id="progress-fill" class="progress-bar-fill" style="width: <?= $progress_pct ?>%;"></div>
            </div>
            <div style="font-size: 11px; color: #64748b; display: flex; justify-content: space-between;">
                <span>Pha: <strong id="val-phase" style="color: <?= ($total_traps >= $target_dp) ? '#34d399' : '#fbbf24' ?>;"><?= ($total_traps >= $target_dp) ? 'WILD HUNT' : 'TAME GENERATION' ?></strong></span>
                <span id="val-progress" style="color: #38bdf8; font-weight: 600;"><?= $progress_pct ?>%</span>
            </div>
        </div>

        <div class="card">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Hashrate Cụm Máy Trạm</div>
            <div class="stat-val" style="color: #34d399;"><span id="val-hashrate"><?= number_format($total_hashrate_mhs, 2) ?></span> <span style="font-size: 13px; font-weight: normal; color: #64748b;">MH/s</span></div>
            <div style="font-size: 11px; color: #94a3b8; margin-top: 10px; display: flex; align-items: center; justify-content: space-between;">
                <span style="display: flex; align-items: center; gap: 6px;">
                    <span class="pulse-dot"></span>
                    <span id="val-workers-count"><?= $active_workers_count ?> Online (<?= count($workers) ?> tổng)</span>
                </span>
                <span style="color: #64748b;">Batch 1,000 DPs</span>
            </div>
        </div>

        <div class="card">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Xác Suất Trúng Giải Hiện Thời</div>
            <div class="stat-val" style="color: #38bdf8;"><span id="val-prob"><?= $prob_info["prob_percent"] ?></span></div>
            <div style="font-size: 11px; color: #94a3b8; margin-top: 10px; display: flex; justify-content: space-between;">
                <span>Kỳ vọng: <strong id="val-odds" style="color: #34d399;"><?= $prob_info["odds_text"] ?></strong></span>
                <span id="val-prob-sci" style="color: #64748b;"><?= $prob_info["prob_scientific"] ?></span>
            </div>
        </div>

        <div class="card">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Cơ Sở Dữ Liệu & Vault</div>
            <div class="stat-val"><span id="val-dbsize"><?= $db_size_mb ?></span> <span style="font-size: 13px; font-weight: normal; color: #64748b;">MB</span></div>
            <div style="font-size: 11px; margin-top: 10px; display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #64748b;"><?= $active_shard_count ?> Shards WITHOUT ROWID</span>
                <?php if ($vault_exists): ?>
                    <span id="val-vault-badge" class="badge badge-green" style="font-size: 11px;">BINGO (bingo_key.php)</span>
                <?php else: ?>
                    <span id="val-vault-badge" class="badge badge-amber" style="font-size: 11px;">ĐANG SĂN</span>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="card" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
        <div>
            <div style="font-weight: 600; font-size: 14px; color: #cbd5e1;">Cấu Hình Ngưỡng Tame (Target DP)</div>
            <div style="font-size: 11px; color: #64748b; margin-top: 3px;">
                Tự động điều phối 2 chiều TAME ↔ WILD.
            </div>
            <div id="target_dp_msg" style="font-size: 11px; margin-top: 4px; display: none;"></div>
        </div>
        <form method="POST" onsubmit="event.preventDefault(); updateTargetDP();" style="display: flex; gap: 8px; flex-wrap: wrap;">
            <input type="number" id="target_dp_input" value="<?= $target_dp ?>" style="background: #0f172a; border: 1px solid #334155; color: #f1f5f9; padding: 7px 12px; border-radius: 4px; font-family: monospace; font-size: 13px; width: 150px;" />
            <button type="submit" style="background: #0284c7; border: none; color: #fff; padding: 7px 14px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600;">Cập nhật</button>
        </form>
    </div>

    <script>
        async function updateTargetDP() {
            const val = document.getElementById('target_dp_input').value;
            const msgEl = document.getElementById('target_dp_msg');
            try {
                const res = await fetch(apiUrl('set_target_dp'), {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target_dp: parseInt(val, 10)})
                });
                const out = await res.json();
                if (msgEl) {
                    msgEl.style.display = 'block';
                    if (res.ok && out.status === 'SUCCESS') {
                        msgEl.style.color = '#34d399';
                        msgEl.innerText = 'Đã cập nhật Target DP = ' + Number(out.target_dp).toLocaleString();
                        await fetchStats();
                    } else {
                        msgEl.style.color = '#f87171';
                        msgEl.innerText = out.message ? String(out.message) : ('HTTP ' + res.status);
                    }
                }
            } catch (err) {
                if (msgEl) {
                    msgEl.style.display = 'block';
                    msgEl.style.color = '#f87171';
                    msgEl.innerText = 'Lỗi kết nối: ' + String(err);
                }
            }
        }
    </script>

    <div class="card">
        <h3 style="margin: 0 0 12px 0; font-size: 15px; color: #cbd5e1;">
            Danh Sách Compute Nodes (Workers)
        </h3>
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>Worker ID</th>
                        <th>Phần Cứng</th>
                        <th>Hashrate</th>
                        <th>Chế Độ</th>
                        <th>DPs Đã Gửi</th>
                        <th>Ping Cuối</th>
                        <th>Trạng Thái</th>
                    </tr>
                </thead>
                <tbody id="workers-tbody">
                    <?php if (empty($workers)): ?>
                        <tr><td colspan="7" style="color: #64748b; text-align: center; padding: 16px;">Chưa có worker nào kết nối. Khởi chạy với: <code>bash run.sh</code></td></tr>
                    <?php else: ?>
                        <?php foreach ($workers as $w): ?>
                            <tr>
                                <td style="color: #38bdf8; font-weight: 600; font-family: monospace;"><?= htmlspecialchars($w["worker_id"]) ?></td>
                                <td><?= htmlspecialchars($w["hardware"]) ?></td>
                                <td style="color: #34d399; font-weight: 600;"><?= htmlspecialchars($w["hashrate"]) ?></td>
                                <td>
                                    <span class="badge <?= ($w["mode"] === "WILD") ? "badge-green" : "badge-amber" ?>">
                                        <?= htmlspecialchars($w["mode"]) ?>
                                    </span>
                                </td>
                                <td><?= number_format($w["total_dps"]) ?></td>
                                <td style="color: #94a3b8; font-size: 12px;"><?= htmlspecialchars($w["last_seen"]) ?></td>
                                <td>
                                    <?php if ($w["is_online"]): ?>
                                        <span class="badge badge-green" style="font-size: 11px;">ONLINE</span>
                                    <?php else: ?>
                                        <span class="badge badge-gray" style="font-size: 11px;">OFFLINE</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>
</html>
