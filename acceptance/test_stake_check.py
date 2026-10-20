"""Stake phase 1: csrmon.stake.check_stake against a fake chain."""
import pytest

from csrmon import molecule, stake
from fakes_stake import DAO, DEAD, FakeChainStake, dao_live, secp_lock

OP = "0x" + "d1" * 32 + ":0"
OWNER = molecule.script_hash(secp_lock(1))


def chain_with(result):
    fc = FakeChainStake()
    fc.live[OP] = result
    return fc


def test_constants():
    assert stake.DAO_TYPE_SCRIPT == DAO
    assert stake.CKB == 10 ** 8


def test_deposited():
    fc = chain_with(dao_live(1, 10_000))
    assert stake.check_stake(fc, OP, min_stake_ckb=10_000, owner_lock_hash=OWNER) == \
        {"status": "deposited", "capacity_ckb": 10_000, "reason": None}
    assert fc.live_calls == [OP]
    # without an owner to compare (attestation time) the lock is not checked
    assert stake.check_stake(chain_with(dao_live(2, 12_345)), OP, min_stake_ckb=10_000)["status"] == "deposited"


def test_upper_case_out_point_is_looked_up_in_lower_case():
    fc = chain_with(dao_live(1, 10_000))
    up = "0x" + "D1" * 32 + ":0"
    assert stake.check_stake(fc, up, min_stake_ckb=1)["status"] == "deposited"
    assert fc.live_calls == [OP]


def test_withdrawn_and_missing():
    assert stake.check_stake(chain_with(DEAD), OP, min_stake_ckb=1) == \
        {"status": "withdrawn", "capacity_ckb": None, "reason": "spent"}
    assert stake.check_stake(FakeChainStake(), OP, min_stake_ckb=1) == \
        {"status": "invalid", "capacity_ckb": None, "reason": "not_found"}


@pytest.mark.parametrize("live,reason,cap", [
    (dao_live(1, 20_000, type_=None), "not_dao", 20_000),
    (dao_live(1, 20_000, type_=dict(DAO, args="0x00")), "not_dao", 20_000),
    (dao_live(1, 20_000, type_=dict(DAO, hash_type="data")), "not_dao", 20_000),
    (dao_live(1, 20_000, data="0x" + "00" * 7 + "01"), "not_deposit", 20_000),    # phase-1 withdrawing cell
    (dao_live(1, 20_000, data="0x"), "not_deposit", 20_000),
    (dao_live(1, 9_999), "too_small", 9_999),
    (dao_live(2, 20_000), "wrong_owner", 20_000),
])
def test_invalid(live, reason, cap):
    assert stake.check_stake(chain_with(live), OP, min_stake_ckb=10_000, owner_lock_hash=OWNER) == \
        {"status": "invalid", "capacity_ckb": cap, "reason": reason}


def test_capacity_boundary_in_shannons():
    live = dao_live(1, 10_000)
    live["cell"]["output"]["capacity"] = hex(10_000 * 10 ** 8 - 1)
    assert stake.check_stake(chain_with(live), OP, min_stake_ckb=10_000)["reason"] == "too_small"


def test_type_hash_case_insensitive():
    live = dao_live(1, 10_000, type_=dict(DAO, code_hash=DAO["code_hash"].upper().replace("0X", "0x")))
    assert stake.check_stake(chain_with(live), OP, min_stake_ckb=10_000)["status"] == "deposited"


def test_bad_out_point_and_rpc_errors():
    with pytest.raises(ValueError):
        stake.check_stake(FakeChainStake(), "nope", min_stake_ckb=1)
    fc = chain_with(dao_live(1, 10_000))
    fc.fail = True
    with pytest.raises(Exception):
        stake.check_stake(fc, OP, min_stake_ckb=1)
