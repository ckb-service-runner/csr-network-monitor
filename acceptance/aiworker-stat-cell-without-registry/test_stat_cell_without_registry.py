"""D41: a stat cell works without the registry (mainnet before 1.x); check-config warns instead of failing."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STAT = {
    "stat_cell_enabled": "true",
    "stat_cell_acp_code_hash": '"0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354"',
    "stat_cell_acp_dep_tx": '"0x4153a2014952d7cac45f285ce9a7c5c0c0e1b21f2d378b82ac1433cb11c25c4d"',
    "stat_cell_sighash_dep_tx": '"0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"',
}


def cfg(tmp_path, **extra):
    base = {"network": '"mainnet"', "public_url": '"https://m.example/mainnet"',
            "db_path": f'"{tmp_path}/t.db"', "key_path": f'"{tmp_path}/k.key"'}
    base.update(extra)
    p = tmp_path / "monitor.toml"
    p.write_text("".join(f"{k} = {v}\n" for k, v in base.items()))
    return str(p)


def check(path):
    return subprocess.run([sys.executable, "-m", "csrmon", "check-config", "--config", path],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_stat_cell_without_registry_is_ok_with_a_warning(tmp_path):
    r = check(cfg(tmp_path, **STAT))
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout
    assert "FLAG_STAKED" in r.stderr


def test_stat_cell_still_needs_its_own_keys(tmp_path):
    bad = dict(STAT)
    del bad["stat_cell_acp_dep_tx"]
    r = check(cfg(tmp_path, **bad))
    assert r.returncode == 2
    assert "stat_cell_acp_dep_tx" in r.stderr


def test_without_stat_cell_no_flag_warning(tmp_path):
    r = check(cfg(tmp_path))
    assert r.returncode == 0
    assert "FLAG_STAKED" not in r.stderr
