"""钱包测试：地址编解码、选币、找零、签名，以及与链的端到端转账。"""

from __future__ import annotations

import unittest

from nimbus_chain.chain import Chain, ChainParams
from nimbus_chain.crypto import hash160
from nimbus_chain.script import p2pkh_script
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.tx import SIGHASH_ALL, TxOut
from nimbus_chain.wallet import (
    ADDRESS_VERSION,
    DUST_THRESHOLD,
    Wallet,
    WalletError,
    address_to_script,
    estimate_fee,
    estimate_size,
    script_to_address,
    transaction_fee,
)

PARAMS = ChainParams(retarget_interval=10_000, coinbase_maturity=1)
MINER_KEY = PrivateKey(0xF00D)
ALICE_KEY = PrivateKey(0xA11CE)
MINER_SCRIPT = p2pkh_script(MINER_KEY.public_key().hash160())


def funded_chain(blocks: int = 4) -> tuple[Chain, Wallet]:
    """建一条链，并把若干 coinbase 付给一个「矿工钱包」。"""
    chain = Chain(PARAMS)
    miner = Wallet(name="miner", keys=[MINER_KEY])
    script = miner.first_script()
    for _ in range(blocks):
        chain.add_block(chain.build_and_mine([], script))
    return chain, miner


class AddressTests(unittest.TestCase):
    def test_roundtrip(self):
        wallet = Wallet(name="a", keys=[ALICE_KEY])
        script = wallet.first_script()
        address = wallet.address()
        self.assertTrue(address.startswith("1"))
        self.assertEqual(address_to_script(address), script)
        self.assertEqual(script_to_address(script), address)

    def test_non_p2pkh_script_has_no_address(self):
        from nimbus_chain.script import op_return_script, p2sh_script
        self.assertIsNone(script_to_address(op_return_script(b"data")))
        self.assertIsNone(script_to_address(p2sh_script(b"\x02" * 20)))
        self.assertIsNone(script_to_address(b"\x51"))

    def test_bad_checksum_rejected(self):
        wallet = Wallet(name="a", keys=[ALICE_KEY])
        address = wallet.address()
        broken = address[:-1] + ("2" if address[-1] != "2" else "3")
        with self.assertRaises(WalletError) as context:
            address_to_script(broken)
        self.assertIn("invalid address", str(context.exception))

    def test_wrong_version_rejected(self):
        from nimbus_chain.crypto import b58check_encode
        testnet_style = b58check_encode(b"\x11" * 20, version=0x6F)
        with self.assertRaises(WalletError) as context:
            address_to_script(testnet_style)
        self.assertIn("version", str(context.exception))

    def test_address_version_constant(self):
        self.assertEqual(ADDRESS_VERSION, 0x00)


class FeeEstimationTests(unittest.TestCase):
    def test_size_grows_with_inputs_and_outputs(self):
        self.assertLess(estimate_size(1, 1), estimate_size(2, 1))
        self.assertLess(estimate_size(1, 1), estimate_size(1, 2))
        self.assertEqual(estimate_size(1, 2), 10 + 148 + 68)

    def test_fee_never_zero(self):
        self.assertEqual(estimate_fee(1, 2, 0.0), 1)
        self.assertGreater(estimate_fee(1, 2, 10.0), estimate_fee(1, 2, 1.0))


class WalletConstructionTests(unittest.TestCase):
    def test_from_secrets_and_hex(self):
        from_secrets = Wallet.from_secrets(1, 2, name="s")
        from_hex = Wallet.from_hex("01", "02", name="h")
        self.assertEqual(from_secrets.key_count, 2)
        self.assertEqual(from_secrets.addresses(), from_hex.addresses())

    def test_new_key(self):
        wallet = Wallet(name="fresh")
        self.assertEqual(wallet.key_count, 0)
        with self.assertRaises(WalletError):
            wallet.address()
        address = wallet.new_key()
        self.assertEqual(wallet.key_count, 1)
        self.assertEqual(wallet.address(), address)
        self.assertEqual(len(wallet.addresses()), 1)

    def test_owns_and_key_lookup(self):
        wallet = Wallet(name="a", keys=[ALICE_KEY])
        self.assertTrue(wallet.owns(wallet.first_script()))
        self.assertFalse(wallet.owns(MINER_SCRIPT))
        self.assertIs(wallet.key_for_script(wallet.first_script()), ALICE_KEY)
        self.assertIsNone(wallet.key_for_script(b"\x51"))
        self.assertIsNone(wallet.key_for_script(MINER_SCRIPT))

    def test_repr_hides_secrets(self):
        wallet = Wallet(name="a", keys=[ALICE_KEY])
        text = repr(wallet)
        self.assertIn("Wallet(", text)
        self.assertNotIn(hex(ALICE_KEY.secret), text)


class BalanceTests(unittest.TestCase):
    def test_balance_and_utxos_after_funding(self):
        chain, miner = funded_chain(blocks=4)
        # 成熟度 1：高度 4 时高度 1~3 的 coinbase 可花，共 3 个
        self.assertEqual(len(miner.utxos(chain)), 3)
        self.assertEqual(miner.balance(chain), 3 * chain.subsidy(1))

    def test_utxos_sorted_by_value_descending(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        values = [entry.value for _, entry in miner.utxos(chain)]
        self.assertEqual(values, sorted(values, reverse=True))

    def test_balance_of_empty_wallet_is_zero(self):
        chain, _ = funded_chain(blocks=2)
        empty = Wallet(name="empty", keys=[PrivateKey(0x123456)])
        self.assertEqual(empty.balance(chain), 0)
        self.assertEqual(empty.utxos(chain), [])


class CoinSelectionTests(unittest.TestCase):
    def test_send_covers_amount_plus_fee(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        before = miner.balance(chain)
        tx = miner.send(chain, alice.address(), 1_000_000, fee_rate=2.0)
        total_out = tx.total_out()
        self.assertGreaterEqual(total_out, 1_000_000)
        self.assertLess(total_out, before)
        fee = transaction_fee(chain, tx)
        self.assertGreaterEqual(fee, estimate_fee(len(tx.inputs), len(tx.outputs), 2.0) - 1)

    def test_change_goes_back_to_wallet(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        tx = miner.send(chain, alice.address(), 1_000_000)
        change_outputs = [out for out in tx.outputs if out.script_pubkey == miner.first_script()]
        self.assertEqual(len(change_outputs), 1)

    def test_dust_change_is_absorbed_into_the_fee(self):
        """找零低于粉尘阈值时不该造出一个永远花不掉的输出。"""
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        utxo_value = miner.utxos(chain)[0][1].value
        # 让找零刚好落在粉尘阈值以下
        amount = utxo_value - estimate_fee(1, 2, 1.0) - (DUST_THRESHOLD - 10)
        tx = miner.send(chain, alice.address(), amount, fee_rate=1.0)
        change_outputs = [out for out in tx.outputs if out.script_pubkey == miner.first_script()]
        self.assertEqual(change_outputs, [])
        fee = transaction_fee(chain, tx)
        self.assertGreater(fee, estimate_fee(1, 2, 1.0))

    def test_insufficient_funds(self):
        chain, miner = funded_chain(blocks=2)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        with self.assertRaises(WalletError) as context:
            miner.send(chain, alice.address(), miner.balance(chain) + 1)
        self.assertIn("insufficient funds", str(context.exception))

    def test_empty_wallet_cannot_send(self):
        chain, _ = funded_chain(blocks=2)
        empty = Wallet(name="empty", keys=[PrivateKey(0x999)])
        with self.assertRaises(WalletError) as context:
            empty.send(chain, Wallet(name="x", keys=[ALICE_KEY]).address(), 1000)
        self.assertIn("no spendable utxos", str(context.exception))

    def test_zero_amount_rejected(self):
        chain, miner = funded_chain(blocks=2)
        with self.assertRaises(WalletError):
            miner.send(chain, Wallet(name="x", keys=[ALICE_KEY]).address(), 0)

    def test_explicit_outputs_and_change_script(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        tx = miner.create_transaction(
            chain,
            [TxOut(500_000, alice.first_script()), TxOut(400_000, MINER_SCRIPT)],
            change_script=MINER_SCRIPT,
        )
        self.assertEqual(len(tx.outputs[:2]), 2)
        self.assertEqual(tx.outputs[1].value, 400_000)

    def test_create_transaction_requires_outputs(self):
        chain, miner = funded_chain(blocks=2)
        with self.assertRaises(WalletError):
            miner.create_transaction(chain, [])


class SigningTests(unittest.TestCase):
    def test_signature_is_valid_for_every_input(self):
        chain, miner = funded_chain(blocks=4)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        # 一笔 coinbase 是 50 NBC，转 70 NBC 必然需要两个输入
        tx = miner.create_transaction(
            chain, [TxOut(7_000_000_000, alice.first_script())])
        self.assertGreaterEqual(len(tx.inputs), 2)
        from nimbus_chain.script import parse_script
        for index in range(len(tx.inputs)):
            elements = parse_script(tx.inputs[index].script_sig)
            signature, public_key = elements
            self.assertEqual(signature[-1], SIGHASH_ALL)   # 签名尾部挂着 hash 类型
            self.assertEqual(len(public_key), 33)
        # 加进 mempool 做完整脚本验证（会真正跑一遍 OP_CHECKSIG）
        from nimbus_chain.mempool import Mempool
        Mempool(chain).add_transaction(tx)

    def test_unsigned_input_is_rejected_by_the_chain(self):
        """丢掉签名后，链上的脚本校验必须拒绝这个区块。"""
        from nimbus_chain.chain import InvalidBlock
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        tx = miner.create_transaction(chain, [TxOut(1_000_000, alice.first_script())])
        tx.inputs[0].script_sig = b""
        block = chain.build_and_mine([tx], MINER_SCRIPT)
        with self.assertRaises(InvalidBlock) as context:
            chain.add_block(block)
        self.assertIn("script verification failed", str(context.exception))

    def test_sighash_uses_the_previous_locking_script(self):
        chain, miner = funded_chain(blocks=2)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        tx = miner.send(chain, alice.address(), 100_000)
        digest = tx.sighash(0, MINER_SCRIPT, SIGHASH_ALL)
        self.assertEqual(len(digest), 32)
        self.assertNotEqual(digest, tx.sighash(0, alice.first_script(), SIGHASH_ALL))


class EndToEndTests(unittest.TestCase):
    def test_transfer_is_confirmed_by_the_chain(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        tx = miner.send(chain, alice.address(), 1_000_000)
        block = chain.build_and_mine([tx], MINER_SCRIPT)
        self.assertEqual(chain.add_block(block).status, "connected")
        self.assertEqual(chain.balance(alice.first_script()), 1_000_000)
        self.assertEqual(chain.confirmations(tx.txid()), 1)

    def test_chained_transfer_across_three_wallets(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        bob = Wallet(name="bob", keys=[PrivateKey(0xB0B)])

        first = miner.send(chain, alice.address(), 2_000_000)
        chain.add_block(chain.build_and_mine([first], MINER_SCRIPT))

        second = alice.send(chain, bob.address(), 900_000)
        second_fee = transaction_fee(chain, second)     # 必须在打包前算（打包后输入已被花掉）
        chain.add_block(chain.build_and_mine([second], MINER_SCRIPT))

        self.assertEqual(chain.balance(bob.first_script()), 900_000)
        self.assertEqual(chain.balance(alice.first_script()),
                         2_000_000 - 900_000 - second_fee)

    def test_op_return_data_rides_along_and_is_not_spendable(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        payload = hash160(b"a document")
        tx = miner.send(chain, alice.address(), 1_000_000, data=payload)
        self.assertIn(payload, tx.data_carrier_outputs())
        block = chain.build_and_mine([tx], MINER_SCRIPT)
        chain.add_block(block)
        self.assertEqual(chain.find_transactions_by_op_return(payload)[0].txid(), tx.txid())
        for _, entry in chain.utxo.items():
            self.assertNotEqual(entry.tx_out.script_pubkey[:1], b"\x6a")

    def test_change_reuseable_in_a_second_transfer(self):
        chain, miner = funded_chain(blocks=3)
        alice = Wallet(name="alice", keys=[ALICE_KEY])
        first = miner.send(chain, alice.address(), 1_000_000)
        chain.add_block(chain.build_and_mine([first], MINER_SCRIPT))
        # 找零回到 miner，因此还能再发一笔
        second = miner.send(chain, alice.address(), 500_000)
        chain.add_block(chain.build_and_mine([second], MINER_SCRIPT))
        self.assertEqual(chain.balance(alice.first_script()), 1_500_000)


if __name__ == "__main__":
    unittest.main()
