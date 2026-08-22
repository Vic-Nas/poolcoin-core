"""Block cycle orchestrator.

One cycle:
  1. drain queue          -- inbound txs and blocks from net_in_q
  2. sync (every 3)      -- pull a better chain from a random peer
  3. vdf.evaluate()      -- blocks ~120s
  4. assemble + broadcast
  5. drain queue (5s)    -- collect peer blocks
  6. pick winner         -- lowest hash among valid blocks
  7. commit              -- swap ChainState, persist, publish view

Flask threads read node.view (a NodeView snapshot). The node loop is the
sole writer; every mutation publishes a new snapshot atomically.
"""

import logging
import queue
import secrets as _secrets
import state as state_mod
import threading
import time

import block as block_mod
import crypto
import mempool as mempool_mod
import pob as pob_mod
import tx as tx_mod
import vdf as vdf_mod
from chainstate import ChainState
from params import BLOCK_SIZE_LIMIT, DB_PATH
from storage import Storage

log = logging.getLogger("ec.node")
_rng = _secrets.SystemRandom()

SYNC_EVERY_N_CYCLES     = 3   # when in sync with peers
SYNC_EVERY_N_CYCLES_NEW = 1   # when behind or no peers yet


# ---------------------------------------------------------------------------
# Tail validation (pure -- no node state touched)
# ---------------------------------------------------------------------------

def _validate_tail(tail, prefix):
    """Validate new blocks against a trusted prefix. Pure: nothing is mutated.

    Returns (True, None) or (False, error_string).
    """
    cs = ChainState.from_chain(prefix) if prefix else ChainState.from_genesis()
    for blk in tail:
        ok, err, cs = cs.validate_and_apply(blk)
        if not ok:
            return False, f"invalid block at {blk['height']}: {err}"
    return True, None


# ---------------------------------------------------------------------------
# StatsAccumulator: owned by Node, updated each commit, read by NodeView
# ---------------------------------------------------------------------------

class StatsAccumulator:
    """Maintains the /api/stats chart data incrementally.

    Owned by Node and updated in _commit() so it always stays current
    without NodeView needing to carry forward state from a previous view.
    Flask reads node.stats (GIL-safe reference) directly.
    """
    from state import compute_reward as _compute_reward

    def __init__(self):
        self.points:    list  = []   # [{height, minted, burned_fees, circulating, net_emission}]
        self._cum:      int   = 0    # cumulative fee burns for incremental update
        self._chain_len: int  = 0    # chain length at last update

    def update(self, chain, state):
        """Extend or rebuild points to match chain. Call after every commit."""
        if len(chain) <= 1:
            self.points, self._cum, self._chain_len = [], 0, len(chain)
            return

        if len(chain) == self._chain_len + 1:
            # Incremental: one new block appended.
            blk    = chain[-1]
            fee    = sum(t["fee"] for t in blk.get("transactions", []))
            prev_minted = self.points[-1]["minted"] if self.points else 0
            reward = state.total_minted - prev_minted
            self._cum += fee
            self.points = self.points + [{
                "height":      blk["height"],
                "minted":      state.total_minted,
                "burned_fees": self._cum,
                "circulating": state.total_minted - self._cum,
                "net_emission": reward - fee,
            }]
        else:
            # Full rebuild (startup, reorg, or first call).
            from state import compute_reward
            points, cum = [], 0
            running_minted = running_burnt = 0
            for blk in chain[1:]:
                fee     = sum(t["fee"] for t in blk.get("transactions", []))
                cum    += fee
                reward  = compute_reward(running_minted, running_burnt)
                running_minted += reward
                running_burnt  += fee
                points.append({
                    "height":      blk["height"],
                    "minted":      running_minted,
                    "burned_fees": cum,
                    "circulating": running_minted - cum,
                    "net_emission": reward - fee,
                })
            if len(points) > 500:
                step   = len(points) / 500
                points = [points[int(i * step)] for i in range(500)]
            self.points, self._cum = points, cum

        self._chain_len = len(chain)


# ---------------------------------------------------------------------------
# CensorshipTracker: owns _exclusion_age, updated each commit
# ---------------------------------------------------------------------------

class CensorshipTracker:
    """Tracks how many consecutive non-full blocks have excluded each pending tx.

    Owned by Node, updated in _commit(). Keeps the censorship-resistance
    feature self-contained instead of scattered across two Node methods.
    """

    def __init__(self):
        self._age: dict = {}  # tx_hash -> consecutive non-full blocks excluding it

    def update(self, confirmed: set, pending: frozenset, block_is_full: bool) -> None:
        """Age up pending-but-unconfirmed txs if block was not full."""
        if not block_is_full:
            for h in pending - confirmed:
                self._age[h] = self._age.get(h, 0) + 1
        # Evict hashes no longer in the mempool.
        self._age = {h: v for h, v in self._age.items() if h in pending}

    def score(self, confirmed: set, pending: frozenset) -> float:
        """Acceptance probability for a block. 1.0 if no long-excluded txs."""
        s = 1.0
        for h in pending - confirmed:
            age = self._age.get(h, 0)
            if age > 0:
                s = min(s, 1.0 / age)
        return s


# ---------------------------------------------------------------------------
# NodeView: read-only snapshot for Flask threads
# ---------------------------------------------------------------------------

class NodeView:
    """Immutable snapshot of node state. Published after every block commit.
    Flask reads node.view -- one reference swap, GIL-atomic, no lock needed.
    stats_points comes from node.stats, not carried here.
    """
    __slots__ = ("chain", "height", "tip", "genesis_hash", "cumulative_score",
                 "state", "burn_window")

    def __init__(self, cs):
        self.chain            = cs.chain
        self.tip              = cs.tip
        self.height           = cs.height
        self.genesis_hash     = cs.genesis_hash
        self.cumulative_score = cs.cumulative_score
        self.state            = cs.state.snapshot()
        self.burn_window      = cs.burn_window


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

class Node:

    def __init__(self, keyfile, public_key, gossip, syncer, pool, net_in_q,
                 db_path=None):
        self.keyfile      = keyfile
        self.pk           = public_key
        self.pk_hex       = public_key.hex()
        self.addr         = crypto.public_key_to_address(public_key)
        self.gossip       = gossip
        self.syncer       = syncer
        self.pool         = pool
        self.net_in_q     = net_in_q
        self.mempool      = mempool_mod.Mempool()
        self.storage      = Storage(db_path or DB_PATH)
        self.running      = False
        self._kek         = None
        self._loop_thread = None
        self._cycle_count      = 0
        self._last_sync_updated = True   # treat first cycle as "just updated" → sync every cycle until caught up

        self._censorship_tracker = CensorshipTracker()

        self.stats = StatsAccumulator()
        self.cs    = self._load_cs()
        self.stats.update(self.cs.chain, self.cs.state)
        self.view  = NodeView(self.cs)

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def _load_cs(self):
        """Load or create ChainState from storage."""
        stored = self.storage.load_all_blocks()
        if not stored:
            cs = ChainState.from_genesis()
            self.storage.save_block(cs.chain[0])
            log.info("[startup] genesis created")
            return cs

        # Backfill tx_bytes for blocks from older databases.
        for blk in stored:
            if "tx_bytes" not in blk:
                blk["tx_bytes"] = sum(tx_mod.tx_size(t)
                                       for t in blk.get("transactions", []))

        if self.storage.state_exists():
            s = state_mod.State.from_snapshot(*self.storage.load_state())
            cs = ChainState.from_storage(stored, s)
        else:
            cs = ChainState.from_chain(stored)

        log.info("[startup] chain loaded  height=%d  tip=%s",
                 cs.height, cs.tip["hash"][:12])
        return cs

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def is_signing_active(self):
        return self._kek is not None

    def mark_tx_seen(self, tx_hash):
        return self.gossip.mark_seen(tx_hash)

    def get_info(self):
        v = self.view
        return {
            "height":       v.height,
            "tip_hash":     v.tip["hash"],
            "genesis_hash": v.genesis_hash,
            "fee_rate":     v.tip["fee_rate"],
            "mempool_size": self.mempool.size(),
            "address":      self.addr,
            "peer_count":   self.pool.count(),
            "total_minted": v.state.total_minted,
            "total_burnt":  v.state.total_burnt,
            "can_mint":     v.state.compute_block_reward(),
        }

    def start(self, kek):
        self._kek         = kek
        self.running      = True
        self._loop_thread = threading.current_thread()
        log.info("[startup] node ready  addr=%s", self.addr)
        try:
            while self.running:
                try:
                    self._run_cycle()
                except Exception:
                    log.exception("[cycle] unhandled error, sleeping 1s")
                    time.sleep(1)
        finally:
            self._kek = None

    def stop(self):
        self.running = False

    def submit_tx(self, tx_dict):
        """Validate and add a tx. Node loop thread only."""
        assert threading.current_thread() is self._loop_thread
        ok, err = tx_mod.validate(tx_dict, self.cs.state,
                                   self.cs.height, self.cs.fee_rate_at)
        if not ok:
            log.debug("[tx] rejected  reason=%s  from=%s",
                      err, tx_dict.get("from", "?")[:24])
            return False, err
        ok, h = self.mempool.add(tx_dict)
        if not ok:
            log.debug("[tx] mempool add failed  reason=%s  from=%s", h,
                      tx_dict.get("from", "?")[:24])
            return False, h
        self.gossip.relay_tx(tx_dict)
        log.info("[tx] accepted  hash=%s  from=%s", h[:12],
                 tx_dict.get("from", "?")[:24])
        return True, h

    def submit_tx_from_api(self, tx_dict, timeout=5):
        """Thread-safe bridge: enqueue tx, block until the loop replies."""
        reply = queue.Queue(maxsize=1)
        self.net_in_q.put({"type": "submit_tx", "tx": tx_dict, "reply": reply})
        try:
            return reply.get(timeout=timeout)
        except queue.Empty:
            return False, "node busy (timeout)"

    def build_and_sign_tx(self, to_outputs, passphrase=None):
        if self._kek is not None:
            kek, own_kek = self._kek, False
        elif passphrase:
            kek, own_kek = crypto.derive_kek(self.keyfile, passphrase), True
        else:
            raise RuntimeError("node not running and no passphrase provided")
        v          = self.view
        nonce      = v.state.get_nonce(self.addr) + 1
        fee_height = v.height
        fee        = tx_mod.compute_fee(self.addr, self.pk_hex, to_outputs,
                                         nonce, fee_height, v.tip["fee_rate"])
        sk = crypto.decrypt_secret_key(self.keyfile, kek=kek)
        t  = tx_mod.create(self.addr, self.pk_hex, to_outputs,
                            nonce, fee_height, fee, sk)
        del sk
        if own_kek:
            del kek
        return t, fee

    # ------------------------------------------------------------------
    # Block cycle
    # ------------------------------------------------------------------

    def _run_cycle(self):
        self._cycle_count += 1
        self._drain_queue()

        # Sync every cycle when no peers yet or when the syncer last updated
        # the chain (meaning we were behind). Every 3 cycles when in sync.
        in_sync = self.pool.count() > 0 and not self._last_sync_updated
        sync_interval = SYNC_EVERY_N_CYCLES if in_sync else SYNC_EVERY_N_CYCLES_NEW
        if self._cycle_count % sync_interval == 0:
            had_peers = self.pool.count() > 0
            updated = self.syncer.check_and_sync(
                self.cs.chain,
                lambda chain: self.apply_better_chain(chain)[0],
            )
            # Only flip the flag when we actually talked to a peer.
            # "No peers available" must not be treated as "already in sync".
            if had_peers:
                self._last_sync_updated = bool(updated)

        cs = self.cs   # local alias -- can change under sync
        pruned = self.mempool.prune_stale(cs.height, cs.state)
        log.info("[vdf] starting height=%d  tip=%s  peers=%d  mempool=%d  pruned=%d",
                 cs.height + 1, cs.tip["hash"][:12],
                 self.pool.count(), self.mempool.size(), len(pruned))

        # Run VDF in a background thread so the node loop stays responsive
        # to tx submissions and peer messages during the ~120s evaluation.
        import concurrent.futures as _cf
        accumulated_blocks = []
        iterations = block_mod.get_vdf_iterations(cs.chain)
        with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
            _fut = _pool.submit(vdf_mod.evaluate,
                                bytes.fromhex(cs.tip["hash"]), iterations)
            while not _fut.done():
                accumulated_blocks += self._drain_queue(timeout=1)
            vdf_out, vdf_proof, vdf_seconds = _fut.result()
        log.info("[vdf] proof ready  height=%d  seconds=%.1f  iterations=%d",
                 cs.height + 1, vdf_seconds, iterations)

        fee_rate   = block_mod.compute_expected_fee_rate(cs.chain)
        sorted_txs = tx_mod.sort_txs(self.mempool.all_txs())
        candidate  = block_mod.assemble(cs.tip, sorted_txs, self.addr,
                                        fee_rate, chain=cs.chain)
        candidate["vdf_output"]    = vdf_out
        candidate["vdf_proof"]     = vdf_proof
        candidate["vdf_seconds"]   = round(vdf_seconds, 2)
        candidate["vdf_iterations"] = iterations
        candidate["hash"]          = block_mod.block_hash(candidate)
        ok, err = block_mod.validate(candidate, cs.state.snapshot(), cs.chain, cs.fee_rate_at)
        if not ok:
            log.error("[vdf] self-produced block failed validation: %s", err)
            return
        self.gossip.broadcast_block(candidate)

        # Drain anything that arrived just as VDF completed, then pick winner.
        # All peer candidates should already be in accumulated_blocks since VDFs
        # take roughly the same time. _drain_queue() with no timeout flushes
        # whatever is already in the queue without blocking.
        peer_blocks = accumulated_blocks + self._drain_queue()
        # Pass cs explicitly — self.cs may have advanced during drain if syncer fired.
        winner, relay = self._pick_winner(cs, candidate, peer_blocks)
        if winner is None:
            return
        self._commit(winner, relay=relay)

    def _pick_winner(self, cs, candidate, peer_blocks):
        """Return (best_block, relay). relay=True means it came from a peer.
        Returns (None, False) if the candidate is stale (tip changed under sync).

        cs: the ChainState candidate was built against — passed explicitly so
        this method is immune to self.cs advancing during the drain window.
        """
        tip     = cs.tip
        pending = self.mempool.pending_hashes()

        valid_peers = []
        for blk in peer_blocks:
            if blk.get("height") != tip["height"] + 1:
                continue
            if blk.get("previous_hash") != tip["hash"]:
                continue
            probe = cs.state.snapshot()
            ok, err = block_mod.validate(blk, probe, cs.chain, cs.fee_rate_at)
            if not ok:
                log.debug("[vdf] peer block rejected: %s", err)
                continue
            confirmed = {tx_mod.tx_hash(t) for t in blk.get("transactions", [])}
            if _rng.random() > self._censorship_tracker.score(confirmed, pending):
                log.debug("[vdf] peer block failed censorship check")
                continue
            log.debug("[vdf] peer block accepted  height=%d  hash=%s  builder=%s  tx=%d",
                      blk["height"], blk["hash"][:12],
                      (blk.get("builder") or "")[:24], len(blk.get("transactions", [])))
            valid_peers.append(blk)

        if candidate.get("previous_hash") != tip["hash"]:
            log.warning("[vdf] candidate stale (tip advanced during drain) — skipping cycle")
            return None, False

        all_valid = valid_peers + [candidate]
        tip_hash_int = pob_mod._tip_hash_int(cs.chain)
        winner = min(all_valid, key=lambda b: (
            cs.burn_window.score(tip_hash_int, b["builder"]), b["hash"]
        ))
        is_peer = winner is not candidate
        log.info("[vdf] winner  hash=%s  peer=%s  candidates=%d  peer_candidates=%d",
                 winner["hash"][:12], is_peer, len(all_valid), len(valid_peers))
        return winner, is_peer

    def _commit(self, blk, relay=False):
        """Append a validated block: update ChainState, persist, publish view."""
        confirmed = {tx_mod.tx_hash(t) for t in blk.get("transactions", [])}
        self.cs = self.cs.apply_block(blk)
        self.storage.save_block_and_state(blk, self.cs.state)
        self.mempool.remove_many(confirmed)
        # Update censorship tracker after remove_many so confirmed txs are
        # already gone from pending — no stale entries linger in _age.
        pending = self.mempool.pending_hashes()
        is_full = blk.get("tx_bytes", 0) >= BLOCK_SIZE_LIMIT * 0.99
        self._censorship_tracker.update(confirmed, pending, is_full)
        self.stats.update(self.cs.chain, self.cs.state)
        self.view = NodeView(self.cs)

        if relay:
            # Peer-won block: broadcast it now. Our own candidate was already
            # broadcast in _run_cycle before the drain window; relay=False there.
            try:
                self.gossip.broadcast_block(blk)
            except Exception:
                log.exception("[commit] relay broadcast failed height=%d", blk["height"])

        log.info("[commit] height=%d  hash=%s  tx=%d  builder=%s",
                 blk["height"], blk["hash"][:12], len(blk["transactions"]),
                 (blk.get("builder") or "")[:24])

    # ------------------------------------------------------------------
    # Queue
    # ------------------------------------------------------------------

    def _drain_queue(self, timeout=0):
        """Drain net_in_q. Returns list of inbound block dicts."""
        assert threading.current_thread() is self._loop_thread
        blocks = []
        try:
            msg = self.net_in_q.get(block=timeout > 0, timeout=timeout or None)
            self._handle(msg, blocks)
        except queue.Empty:
            return blocks
        while True:
            try:
                self._handle(self.net_in_q.get_nowait(), blocks)
            except queue.Empty:
                break
        return blocks

    def _handle(self, msg, block_out):
        """Dispatch one queue message."""
        t = msg.get("type")
        if t == "block":
            block_out.append(msg["block"])
        elif t == "submit_tx":
            msg["reply"].put(self.submit_tx(msg["tx"]))
        elif t == "tx":
            self._handle_inbound_tx(msg)

    def _handle_inbound_tx(self, msg):
        """Route an inbound tx message.

        Stem txs (Dandelion relay) are forwarded without validation — we are
        not the ultimate recipient, just a relay node. Fluff txs are validated
        and added to the mempool if new and valid.
        """
        tx_dict   = msg["tx"]
        sender    = tx_dict.get("from", "?")[:24]
        remaining = msg.get("remaining_hops", 0)
        if msg.get("relay_type") == "tx_stem" and remaining > 0:
            log.debug("[tx] stem relay  hops_remaining=%d  from=%s", remaining, sender)
            self.gossip.dandelion_send(tx_dict, remaining)
            return
        ok, err = tx_mod.validate(tx_dict, self.cs.state,
                                   self.cs.height, self.cs.fee_rate_at)
        if not ok:
            log.debug("[tx] inbound rejected  reason=%s  from=%s", err, sender)
            return
        added, h_or_err = self.mempool.add(tx_dict)
        if added:
            log.debug("[tx] inbound accepted  hash=%s  from=%s", h_or_err[:12], sender)
            self.gossip.relay_tx(tx_dict)
        else:
            log.debug("[tx] inbound duplicate  from=%s", sender)

    # ------------------------------------------------------------------
    # Chain sync / reorg
    # ------------------------------------------------------------------

    def _evaluate_remote_chain(self, remote_chain):
        """Pure evaluation of a candidate remote chain. No state is mutated.

        Returns (ok, err, fork_point, tail, remote_cs) on success,
        or (False, err, None, None, None) on rejection.

        Order of operations matters for security:
          1. Genesis check  — cheap, stops wrong-network chains immediately.
          2. Fork point     — O(min(local, remote)) hash comparisons.
          3. _validate_tail — structural block validation on untrusted data.
          4. from_chain     — trusted replay, only runs on validated blocks.
          5. is_better_than — fork choice, only after we know it's valid.
        """
        if not remote_chain or remote_chain[0]["hash"] != self.cs.genesis_hash:
            log.warning("[sync] rejected genesis mismatch  remote=%s  expected=%s",
                        (remote_chain[0]["hash"][:12] if remote_chain else "empty"),
                        self.cs.genesis_hash[:12])
            return False, "genesis mismatch", None, None, None

        fork_point = next(
            (i for i, (a, b) in enumerate(zip(self.cs.chain, remote_chain))
             if a["hash"] != b["hash"]),
            min(len(self.cs.chain), len(remote_chain))
        )
        tail = remote_chain[fork_point:]

        ok, err = _validate_tail(tail, remote_chain[:fork_point])
        if not ok:
            log.warning("[sync] rejected: %s", err)
            return False, err, None, None, None

        try:
            remote_cs = ChainState.from_chain(remote_chain)
        except Exception as e:
            log.warning("[sync] chain replay failed: %s", e)
            return False, f"chain replay error: {e}", None, None, None

        if not remote_cs.is_better_than(self.cs, fork_point=fork_point):
            log.debug("[sync] remote chain not better  remote_h=%d  local_h=%d  remote_score=%d  local_score=%d",
                      remote_cs.height, self.cs.height,
                      remote_cs.cumulative_score, self.cs.cumulative_score)
            return False, "remote chain not better", None, None, None

        return True, None, fork_point, tail, remote_cs

    def apply_better_chain(self, remote_chain):
        """Accept remote_chain if it is better than local. Used by syncer."""
        ok, err, fork_point, tail, remote_cs = self._evaluate_remote_chain(remote_chain)
        if not ok:
            return False, err

        # Storage write first — if it fails, mempool stays consistent with self.cs.
        self.storage.replace_chain_and_state(fork_point, tail, remote_cs.state)
        self._reorg_mempool(fork_point, remote_chain)
        self.cs = remote_cs
        self.stats.update(self.cs.chain, self.cs.state)
        self.view = NodeView(self.cs)

        if fork_point < self.cs.height:
            log.warning("[reorg] height=%d  fork_point=%d", self.cs.height, fork_point)
        else:
            log.info("[sync] height=%d  fork_point=%d", self.cs.height, fork_point)
        return True, None

    def _reorg_mempool(self, fork_point, new_chain):
        old_txs = {tx_mod.tx_hash(t): t
                   for blk in self.cs.chain[fork_point:]
                   for t in blk.get("transactions", [])}
        new_confirmed = {tx_mod.tx_hash(t)
                         for blk in new_chain[fork_point:]
                         for t in blk.get("transactions", [])}
        self.mempool.remove_many(new_confirmed)
        for h, t in old_txs.items():
            if h not in new_confirmed:
                self.mempool.add(t)
