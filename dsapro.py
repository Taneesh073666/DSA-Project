import sys
import math
from collections import defaultdict

sys.setrecursionlimit(10000)   # Tarjan / segment-tree recursion safety for longer chains

# ==========================================
# 1. DATA MODELS
# ==========================================

class Transaction:
    def __init__(self, tx_id, sender, receiver, amount, timestamp, original_time_str):
        self.id = tx_id
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = timestamp
        self.original_time_str = original_time_str

    def __str__(self):
        return f"Tx #{self.id:<2} | {self.sender:<12} -> {self.receiver:<12} | ${self.amount:>9.2f} | Time = {self.original_time_str} ({self.timestamp} min)"


class TemporalEdge:
    def __init__(self, tx_id, target, amount, timestamp, time_str):
        self.tx_id = tx_id
        self.target = target
        self.amount = amount
        self.timestamp = timestamp
        self.time_str = time_str


# ==========================================
# 2. SEGMENT TREE (TEMPORAL INDEX ENGINE)
# ==========================================

class SegmentTreeNode:
    def __init__(self, start_time, end_time):
        self.start_time = start_time
        self.end_time = end_time
        self.tx_indices = []
        self.left = None
        self.right = None


class SegmentTree:
    def __init__(self, min_time, max_time):
        self.root = self._build_tree(min_time, max_time)

    def _build_tree(self, start, end):
        if start > end:
            return None
        node = SegmentTreeNode(start, end)
        if start == end:
            return node
        mid = (start + end) // 2
        node.left = self._build_tree(start, mid)
        node.right = self._build_tree(mid + 1, end)
        return node

    def insert(self, tx):
        self._insert_recursive(self.root, tx)

    def _insert_recursive(self, node, tx):
        if not node or tx.timestamp < node.start_time or tx.timestamp > node.end_time:
            return
        node.tx_indices.append(tx.id)
        if node.start_time == node.end_time:
            return
        mid = (node.start_time + node.end_time) // 2
        if tx.timestamp <= mid:
            self._insert_recursive(node.left, tx)
        else:
            self._insert_recursive(node.right, tx)

    # ---- NEW: real O(log N + k) range query ----
    def query(self, l, r):
        """Return the set of transaction IDs whose timestamp lies in [l, r]."""
        return self._query(self.root, l, r)

    def _query(self, node, l, r):
        if not node or not node.tx_indices:            # empty subtree: prune
            return set()
        if r < node.start_time or l > node.end_time:   # no overlap
            return set()
        if l <= node.start_time and node.end_time <= r:  # fully covered: return whole bucket
            return set(node.tx_indices)
        return self._query(node.left, l, r) | self._query(node.right, l, r)

    def print_tree_summary(self):
        print("\n+---------------------------------------------------------------------------------+")
        print("|            SEGMENT TREE TEMPORAL HIERARCHY INDEX (O(log N) QUERY ENGINE)         |")
        print("+---------------------------------------------------------------------------------+")
        self._print_node_clean(self.root, "", True)
        print("+---------------------------------------------------------------------------------+\n")

    def _print_node_clean(self, node, prefix, is_tail):
        if not node:
            return
        if node.tx_indices:
            connector = "└── " if is_tail else "├── "
            print(f"{prefix}{connector}[{node.start_time}m - {node.end_time}m] Total Indexed Pointers: {len(node.tx_indices)} {node.tx_indices}")

        children = []
        if node.left and node.left.tx_indices:
            children.append(node.left)
        if node.right and node.right.tx_indices:
            children.append(node.right)

        for i, child in enumerate(children):
            extension = "    " if is_tail else "│   "
            self._print_node_clean(child, prefix + extension, i == len(children) - 1)


# ==========================================
# 3. DYNAMIC TEMPORAL MULTI-DIRECTED GRAPH
# ==========================================

class TemporalMultiGraph:
    def __init__(self):
        self.adj_list = defaultdict(list)

    def add_edge(self, sender, receiver, amount, timestamp, time_str, tx_id):
        if receiver not in self.adj_list:
            self.adj_list[receiver] = []
        self.adj_list[sender].append(TemporalEdge(tx_id, receiver, amount, timestamp, time_str))

    def print_dynamic_graph_topology(self):
        print("\n+---------------------------------------------------------------------------------+")
        print("|             DYNAMIC TEMPORAL MULTI-DIRECTED GRAPH TOPOLOGY MAP                  |")
        print("+---------------------------------------------------------------------------------+")

        if not self.adj_list:
            print(" Graph is currently empty. Please input transactions first.")
            print("+---------------------------------------------------------------------------------+\n")
            return

        for node in sorted(self.adj_list.keys()):
            edges = self.adj_list[node]
            print(f"\n [ Account Node: {node.upper()} ]")
            if not edges:
                print("   └── (Sink Account / Cash-out Node - No Outgoing Transfers)")
            else:
                for i, e in enumerate(edges):
                    connector = "   └── " if i == len(edges) - 1 else "   ├── "
                    print(f"{connector}──( Tx #{e.tx_id:<2} | ${e.amount:>9.2f} | Time={e.time_str} )──► [ {e.target.upper()} ]")
        print("+---------------------------------------------------------------------------------+\n")


# ==========================================
# 4. FORENSIC FRAUD ENGINE & NETWORK SUMMARY
# ==========================================

class ForensicReport:
    def __init__(self, start, edges, total_duration, total_volume_in, total_volume_out,
                 retention_ratio, risk_score, risk_category, typology_tag):
        self.start = start                    # starting account (lower case)
        self.edges = edges                    # list of TemporalEdge, in time order
        self.total_duration = total_duration
        self.total_volume_in = total_volume_in
        self.total_volume_out = total_volume_out
        self.retention_ratio = retention_ratio
        self.risk_score = risk_score
        self.risk_category = risk_category
        self.typology_tag = typology_tag

    @property
    def hops(self):
        return len(self.edges)

    def path_string(self):
        parts = [self.start.upper()]
        for e in self.edges:
            parts.append(f"--[{e.time_str}, ${e.amount:.2f}]--> {e.target.upper()}")
        return " ".join(parts)


class FraudDetector:
    MAX_HOPS = 10          # depth cap for chain search (keeps worst case bounded)

    def __init__(self):
        self.index = 0
        self.indices = {}
        self.low_link = {}
        self.stack = []
        self.on_stack = set()
        self.scc_list = []

    # ---------- Engine 1: Tarjan SCC ----------
    def find_mule_rings(self, graph):
        self.indices.clear()
        self.low_link.clear()
        self.stack.clear()
        self.on_stack.clear()
        self.scc_list.clear()
        self.index = 0

        for node in list(graph.adj_list.keys()):
            if node not in self.indices:
                self._strong_connect(node, graph)

        return [scc for scc in self.scc_list if len(scc) > 1]

    def _strong_connect(self, u, graph):
        self.indices[u] = self.index
        self.low_link[u] = self.index
        self.index += 1
        self.stack.append(u)
        self.on_stack.add(u)

        for edge in graph.adj_list.get(u, []):
            v = edge.target
            if v not in self.indices:
                self._strong_connect(v, graph)
                self.low_link[u] = min(self.low_link[u], self.low_link[v])
            elif v in self.on_stack:
                self.low_link[u] = min(self.low_link[u], self.indices[v])

        if self.low_link[u] == self.indices[u]:
            scc = []
            while True:
                w = self.stack.pop()
                self.on_stack.remove(w)
                scc.append(w)                     # kept lower case; upper-cased only when printing
                if w == u:
                    break
            self.scc_list.append(scc)

    # ---------- NEW: computed ring score (replaces hard-coded 95) ----------
    def score_ring(self, ring, graph):
        members = set(ring)
        volume = 0.0
        times = []
        for u in ring:
            for e in graph.adj_list.get(u, []):
                if e.target in members:
                    volume += e.amount
                    times.append(e.timestamp)
        span = (max(times) - min(times)) if times else 0

        size_pts = min(40, 10 * len(ring))                      # bigger ring = more layered
        if volume >= 100000: vol_pts = 30
        elif volume >= 10000: vol_pts = 20
        else: vol_pts = 10
        if span <= 60: vel_pts = 30
        elif span <= 240: vel_pts = 20
        else: vel_pts = 10

        score = size_pts + vol_pts + vel_pts
        if score >= 75: category = "CRITICAL RISK"
        elif score >= 50: category = "HIGH RISK"
        else: category = "MEDIUM RISK"
        return score, category, volume, span

    # ---------- Engine 2: maximal time-respecting chains ----------
    def find_maximal_chains(self, graph, breach_time_minutes):
        """All time-respecting chains with >= 2 hops that cannot be extended,
        with chains that are just a part of a longer chain removed."""
        chains = []

        def dfs(start, node, last_time, visited, path):
            extended = False
            if len(path) < self.MAX_HOPS:
                for e in graph.adj_list.get(node, []):
                    if e.target not in visited and e.timestamp >= last_time and e.timestamp >= breach_time_minutes:
                        extended = True
                        visited.add(e.target)
                        path.append(e)
                        dfs(start, e.target, e.timestamp, visited, path)
                        path.pop()
                        visited.remove(e.target)
            if not extended and len(path) >= 2:
                chains.append((start, list(path)))

        for start in list(graph.adj_list.keys()):
            dfs(start, start, breach_time_minutes, {start}, [])

        keys = [tuple(e.tx_id for e in p) for _, p in chains]

        def is_part_of(a, b):
            return len(a) < len(b) and any(b[i:i + len(a)] == a for i in range(len(b) - len(a) + 1))

        return [c for c, k in zip(chains, keys) if not any(is_part_of(k, other) for other in keys)]

    def analyze_advanced_money_trails(self, graph, breach_time_minutes):
        reports = []

        for start, edges in self.find_maximal_chains(graph, breach_time_minutes):
            initial_amount = edges[0].amount
            final_amount = edges[-1].amount
            duration = edges[-1].timestamp - edges[0].timestamp
            retention_ratio = (final_amount / initial_amount) * 100.0 if initial_amount else 0.0

            risk_score = 0
            if duration <= 10: risk_score += 40
            elif duration <= 30: risk_score += 30
            elif duration <= 60: risk_score += 15
            else: risk_score += 5

            if 90.0 <= retention_ratio <= 100.0: risk_score += 30      # FIXED: includes 99-100%
            elif retention_ratio >= 80.0: risk_score += 20
            else: risk_score += 10

            hops = len(edges)
            if hops >= 4: risk_score += 30
            elif hops == 3: risk_score += 20
            else: risk_score += 10

            if risk_score >= 75:
                risk_category = "CRITICAL RISK"
                typology_tag = "Automated High-Velocity Bot Layering"
            elif risk_score >= 50:
                risk_category = "HIGH RISK"
                typology_tag = "Paid Human Mule Commission Pass-Through"
            elif risk_score >= 35:
                risk_category = "MEDIUM RISK"
                typology_tag = "Delayed Intermediary Transfer (Needs Monitoring)"
            else:
                risk_category = "LOW RISK"
                typology_tag = "Normal Sequential Commercial / Individual Payment Pace"

            reports.append(ForensicReport(start, edges, duration, initial_amount, final_amount,
                                          retention_ratio, risk_score, risk_category, typology_tag))

        reports.sort(key=lambda r: r.risk_score, reverse=True)   # most dangerous first
        return reports

    # ---------- Network summary (receives already-filtered post-breach transactions) ----------
    def print_network_and_volume_summary(self, post_transactions, breach_time_minutes):
        unique_accounts = set()
        out_count = defaultdict(int)
        in_count = defaultdict(int)
        sent_vol = defaultdict(float)
        recv_vol = defaultdict(float)

        min_time = float('inf')
        max_time = float('-inf')

        for tx in post_transactions:
            u = tx.sender.upper()
            v = tx.receiver.upper()

            unique_accounts.add(u)
            unique_accounts.add(v)

            out_count[u] += 1
            in_count[v] += 1
            sent_vol[u] += tx.amount
            recv_vol[v] += tx.amount

            min_time = min(min_time, tx.timestamp)
            max_time = max(max_time, tx.timestamp)

        if min_time == float('inf'): min_time = breach_time_minutes
        if max_time == float('-inf'): max_time = breach_time_minutes

        print(">>> [NETWORK & VOLUME SUMMARY]")
        print(f"NETWORK: {len(unique_accounts)} accounts, {len(post_transactions)} post-breach transactions, time span {min_time}-{max_time} min")
        print(f"{'Account':<14} {'Out#':>5} {'In#':>5} {'Sent($)':>14} {'Received($)':>14}")

        for acc in sorted(unique_accounts):
            print(f"{acc:<14} {out_count[acc]:>5} {in_count[acc]:>5} {sent_vol[acc]:>14.2f} {recv_vol[acc]:>14.2f}")


# ==========================================
# 5. MAIN MENU SYSTEM
# ==========================================

def convert_time_to_minutes(time_str):
    """'HH:mm' -> minutes after midnight. Raises ValueError if malformed or out of range."""
    parts = time_str.strip().split(":")
    if len(parts) != 2:
        raise ValueError("Time must be in HH:mm format (e.g. 08:35).")
    try:
        hours = int(parts[0])
        minutes = int(parts[1])
    except ValueError:
        raise ValueError("Time must be in HH:mm format (e.g. 08:35).")
    if not (0 <= hours <= 23 and 0 <= minutes <= 59):
        raise ValueError("Time out of range: hours must be 00-23 and minutes 00-59.")
    return hours * 60 + minutes


def main():
    master_transactions = []
    segment_tree = SegmentTree(0, 1440)
    global_graph = TemporalMultiGraph()
    tx_counter = 1

    while True:
        print("==================================================================================")
        print("   ENTERPRISE AML SURVEILLANCE & FINANCIAL FRAUD ENGINE (V3.0)")
        print("==================================================================================")
        print("  1. Batch Ingest Transactions")
        print("  2. Display Dynamic Multi-Directed Graph Topology")
        print("  3. Display Segment Tree Index Summary")
        print("  4. Execute Breach Analysis & Composite Forensic Audit")
        print("  5. Clear Memory Buffer")
        print("  6. Exit")
        print("==================================================================================")

        try:
            choice = int(input("Select action (1-6): ").strip())
        except ValueError:
            print("\n[!] Invalid input. Select a number between 1 and 6.\n")
            continue

        if choice == 1:
            print("\n----------------------------------------------------------------------------------")
            print("TRANSACTION INGESTION MODE")
            print("Format: Sender Receiver Amount Timestamp(HH:mm)")
            print("Example: ACC_A ACC_B 5000 08:35")
            print("Type 'DONE' when batch input is complete.")
            print("----------------------------------------------------------------------------------")

            while True:
                line = input(f"Ingest Tx #{tx_counter} > ").strip()
                if line.upper() == "DONE":
                    break
                if not line:
                    continue

                parts = line.split()
                if len(parts) != 4:
                    print("   [!] Format Error! Expected exactly: Sender Receiver Amount Timestamp(HH:mm)")
                    continue

                try:
                    sender = parts[0].lower()
                    receiver = parts[1].lower()
                    try:
                        amount = float(parts[2])
                    except ValueError:
                        raise ValueError("Amount must be a number.")
                    if not math.isfinite(amount) or amount <= 0:
                        raise ValueError("Amount must be a positive number.")
                    if sender == receiver:
                        raise ValueError("Sender and receiver must be different accounts.")
                    time_str = parts[3]
                    timestamp_minutes = convert_time_to_minutes(time_str)
                except ValueError as err:
                    print(f"   [!] Rejected: {err}")
                    continue

                tx = Transaction(tx_counter, sender, receiver, amount, timestamp_minutes, time_str)
                master_transactions.append(tx)
                segment_tree.insert(tx)
                global_graph.add_edge(sender, receiver, amount, timestamp_minutes, time_str, tx.id)

                print(f"   [+] Ingested: {tx}")
                tx_counter += 1

            print(f"\n[+] Ingestion complete. Total Records: {len(master_transactions)}\n")

        elif choice == 2:
            global_graph.print_dynamic_graph_topology()

        elif choice == 3:
            segment_tree.print_tree_summary()

        elif choice == 4:
            if not master_transactions:
                print("\n[!] No transaction data in memory. Please ingest transactions first (Option 1).\n")
                continue

            breach_time_str = input("\nEnter Breach Timestamp (24hr format HH:mm, e.g. 08:35): ").strip()
            try:
                breach_time_minutes = convert_time_to_minutes(breach_time_str)
            except ValueError as err:
                print(f"[!] {err}\n")
                continue

            print("\n==================================================================================")
            print(f"          ENTERPRISE AML FORENSIC AUDIT (POST-BREACH TIME: {breach_time_str})")
            print("==================================================================================")

            # Segment-tree range query selects post-breach transactions in O(log N + k)
            post_ids = segment_tree.query(breach_time_minutes, 1440)
            post_transactions = [tx for tx in master_transactions if tx.id in post_ids]
            print(f"[i] Segment tree query [{breach_time_minutes}m - 1440m] returned {len(post_transactions)} post-breach transaction(s).")

            breach_graph = TemporalMultiGraph()
            for tx in post_transactions:
                breach_graph.add_edge(tx.sender, tx.receiver, tx.amount, tx.timestamp, tx.original_time_str, tx.id)

            detector = FraudDetector()

            # 1. Tarjan's SCC Engine
            print("\n>>> [ENGINE 1] TARJAN'S SCC CYCLIC LAUNDERING ENGINE (POST-BREACH)")
            mule_rings = detector.find_mule_rings(breach_graph)

            if not mule_rings:
                print("    [STATUS: CLEAN] No circular mule rings identified post-breach.")
            else:
                for ring in mule_rings:
                    score, category, volume, span = detector.score_ring(ring, breach_graph)
                    print(f"\n    [!] ALERT LEVEL: {category} (COMPOSITE SCORE: {score}/100)")
                    print(f"        • Ring Entities      : {[n.upper() for n in ring]}")
                    print("        • Topology Pattern   : Closed Multi-Node Circular Loop")
                    print(f"        • Ring Volume        : ${volume:.2f} circulating over {span} minutes")
                    print("        • Forensic Mechanism : Money is routed back to originating entities to artificially")
                    print("                               inflate trading volume and obscure true ownership.")
                    if score >= 75:
                        print("        • Compliance Action  : IMMEDIATE ACCOUNT FREEZE & SAR (Suspicious Activity Report) FILING.")
                    else:
                        print("        • Compliance Action  : Flag for manual compliance review; consider SAR.")

            # 2. Time-Constrained Velocity Engine
            print("\n>>> [ENGINE 2] TIME-CONSTRAINED VELOCITY & FLOW CONSERVATION ANALYSIS")
            reports = detector.analyze_advanced_money_trails(breach_graph, breach_time_minutes)

            if not reports:
                print("    [STATUS: CLEAN] No post-breach pass-through chains detected.")
            else:
                for r in reports:
                    print(f"\n    [!] RISK ASSESSMENT: {r.risk_category} (Risk Score: {r.risk_score}/100)")
                    print(f"        • Typology Tag   : {r.typology_tag}")
                    print(f"        • Path Traversed : {r.path_string()}")
                    print(f"        • Layer Count    : {r.hops} hops ({r.hops - 1} intermediate account(s))")
                    print(f"        • Duration       : {r.total_duration} minutes post-breach")
                    print(f"        • Flow Conserved : {r.retention_ratio:.1f}% (${r.total_volume_in:.2f} In -> ${r.total_volume_out:.2f} Out)")
                    action = "Automated block on cashout node." if r.risk_score >= 75 else (
                             "Flag for manual compliance review." if r.risk_score >= 35 else "No action required (Normal transaction flow).")
                    print(f"        • Action Required: {action}")

            # 3. Dynamic Network & Volume Summary Table
            print()
            detector.print_network_and_volume_summary(post_transactions, breach_time_minutes)

            print("\n==================================================================================")
            print("                               AUDIT COMPLETE                                     ")
            print("==================================================================================\n")

        elif choice == 5:
            master_transactions.clear()
            segment_tree = SegmentTree(0, 1440)
            global_graph = TemporalMultiGraph()
            tx_counter = 1
            print("\n[+] System memory buffer cleared.\n")

        elif choice == 6:
            print("\n[+] Shutting down engine. System offline.")
            sys.exit(0)

        else:
            print("\n[!] Invalid option.\n")


if __name__ == "__main__":
    main()