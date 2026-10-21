import sys
from collections import defaultdict

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

    # Time Complexity: O(1)
    def __str__(self):
        return f"Tx #{self.id:<2} | {self.sender:<12} -> {self.receiver:<12} | ${self.amount:>9.2f} | Time = {self.original_time_str} ({self.timestamp} min)"


class TemporalEdge:
    # Time Complexity: O(1)
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
    # Time Complexity: O(1)
    def __init__(self, start_time, end_time):
        self.start_time = start_time
        self.end_time = end_time
        self.tx_indices = []
        self.left = None
        self.right = None


class SegmentTree:
    # Time Complexity: O(M) where M is the timeline range
    def __init__(self, min_time, max_time):
        self.root = self._build_tree(min_time, max_time)

    # Time Complexity: O(M)
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

    # Time Complexity: O(log M)
    def insert(self, tx):
        self._insert_recursive(self.root, tx)

    # Time Complexity: O(log M)
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

    # Time Complexity: O(N)
    def print_tree_summary(self):
        print("\n+---------------------------------------------------------------------------------+")
        print("|            SEGMENT TREE TEMPORAL HIERARCHY INDEX (O(log N) QUERY ENGINE)         |")
        print("+---------------------------------------------------------------------------------+")
        self._print_node_clean(self.root, "", True)
        print("+---------------------------------------------------------------------------------+\n")

    # Time Complexity: O(N)
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
    # Time Complexity: O(1)
    def __init__(self):
        self.adj_list = defaultdict(list)

    # Time Complexity: O(1) amortized
    def add_edge(self, sender, receiver, amount, timestamp, time_str, tx_id):
        if receiver not in self.adj_list:
            self.adj_list[receiver] = []
        self.adj_list[sender].append(TemporalEdge(tx_id, receiver, amount, timestamp, time_str))

    # Time Complexity: O(V log V + E)
    def print_dynamic_graph_topology(self):
        print("\n+---------------------------------------------------------------------------------+")
        print("|              DYNAMIC TEMPORAL MULTI-DIRECTED GRAPH TOPOLOGY MAP                  |")
        print("+---------------------------------------------------------------------------------+")

        if not self.adj_list:
            print(" Graph is currently empty. Please input transactions first.")
            print("+---------------------------------------------------------------------------------+\n")
            return

        for node in sorted(self.adj_list.keys()):
            edges = self.adj_list[node]
            print(f"\n [ Account Node: {node.upper()} ]")
            if not edges:
                print("    └── (Sink Account / Cash-out Node - No Outgoing Transfers)")
            else:
                for i, e in enumerate(edges):
                    connector = "    └── " if i == len(edges) - 1 else "    ├── "
                    print(f"{connector}──( Tx #{e.tx_id:<2} | ${e.amount:>9.2f} | Time={e.time_str} )──► [ {e.target.upper()} ]")
        print("+---------------------------------------------------------------------------------+\n")


# ==========================================
# 4. FORENSIC FRAUD ENGINE & NETWORK SUMMARY
# ==========================================

class PathStep:
    # Time Complexity: O(1)
    def __init__(self, node, time, time_str, amount):
        self.node = node
        self.time = time
        self.time_str = time_str
        self.amount = amount


class ForensicReport:
    # Time Complexity: O(1)
    def __init__(self, path, total_duration, total_volume_in, total_volume_out, retention_ratio, risk_category, typology_tag, hidden_score):
        self.path = path
        self.total_duration = total_duration
        self.total_volume_in = total_volume_in
        self.total_volume_out = total_volume_out
        self.retention_ratio = retention_ratio
        self.risk_category = risk_category
        self.typology_tag = typology_tag
        self.hidden_score = hidden_score


class FraudDetector:
    # Time Complexity: O(1)
    def __init__(self):
        self.index = 0
        self.indices = {}
        self.low_link = {}
        self.stack = []
        self.on_stack = set()
        self.scc_list = []

    # Time Complexity: O(V + E)
    def find_mule_rings(self, graph):
        self.indices.clear()
        self.low_link.clear()
        self.stack.clear()
        self.on_stack.clear()
        self.scc_list.clear()
        self.index = 0

        for node in graph.adj_list.keys():
            if node not in self.indices:
                self._strong_connect(node, graph)

        return [scc for scc in self.scc_list if len(scc) > 1]

    # Time Complexity: O(V + E) cumulative
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
                scc.append(w.upper())
                if w == u:
                    break
            self.scc_list.append(scc)

    # Time Complexity: O(V * (V + E)) worst-case for path search.
    def analyze_advanced_money_trails(self, graph, breach_time_minutes):
        raw_reports = []

        def dfs_trail(current, current_time, visited, current_path):
            found_extension = False
            for edge in graph.adj_list.get(current, []):
                if edge.target not in visited and edge.timestamp >= breach_time_minutes and edge.timestamp >= current_time:
                    found_extension = True
                    step = PathStep(edge.target.upper(), edge.timestamp, edge.time_str, edge.amount)
                    dfs_trail(edge.target, edge.timestamp, visited | {edge.target}, current_path + [step])

            if not found_extension and len(current_path) >= 3:
                initial_amount = current_path[0].amount
                final_amount = current_path[-1].amount
                
                # --- STRICT FLOW CONSERVATION FILTER ---
                # If flow out is greater than flow in, it violates layering typology (pooling, not pass-through)
                if final_amount > initial_amount:
                    return

                duration = current_path[-1].time - current_path[0].time
                retention_ratio = (final_amount / initial_amount) * 100.0 if initial_amount > 0 else 0.0

                internal_score = 0
                if duration <= 10: internal_score += 40
                elif duration <= 30: internal_score += 30
                elif duration <= 60: internal_score += 15
                else: internal_score += 5

                if 90.0 <= retention_ratio <= 99.0: internal_score += 30
                elif retention_ratio >= 80.0: internal_score += 20
                else: internal_score += 10

                hops = len(current_path) - 1
                if hops >= 4: internal_score += 30
                elif hops == 3: internal_score += 20
                else: internal_score += 10

                if internal_score >= 75:
                    risk_category = "CRITICAL RISK"
                    typology_tag = "Automated High-Velocity Bot Layering"
                elif internal_score >= 50:
                    risk_category = "HIGH RISK"
                    typology_tag = "Paid Human Mule Commission Pass-Through"
                elif internal_score >= 35:
                    risk_category = "NEEDS MONITORING"
                    typology_tag = "Delayed Intermediary Transfer"
                else:
                    risk_category = "LOW RISK"
                    typology_tag = "Normal Sequential Commercial / Individual Payment Pace"

                raw_reports.append(ForensicReport(current_path, duration, initial_amount, final_amount,
                                               retention_ratio, risk_category, typology_tag, internal_score))

        for start_node in graph.adj_list.keys():
            for edge in graph.adj_list.get(start_node, []):
                if edge.timestamp >= breach_time_minutes:
                    first_step = PathStep(start_node.upper(), edge.timestamp, edge.time_str, edge.amount)
                    second_step = PathStep(edge.target.upper(), edge.timestamp, edge.time_str, edge.amount)
                    dfs_trail(edge.target, edge.timestamp, {start_node, edge.target}, [first_step, second_step])

        # --- DEDUPLICATION & FILTERING ---
        filtered_reports = [r for r in raw_reports if r.risk_category in ["CRITICAL RISK", "NEEDS MONITORING"]]

        best_routes = {}
        for r in filtered_reports:
            start_node = r.path[0].node
            end_node = r.path[-1].node
            route_pair = (start_node, end_node)
            
            # Keep only the highest risk variation of a specific Start-to-End money path
            if route_pair not in best_routes or r.hidden_score > best_routes[route_pair].hidden_score:
                best_routes[route_pair] = r

        return list(best_routes.values())

    # Time Complexity: O(T + A log A) 
    def print_network_and_volume_summary(self, transactions, breach_time_minutes):
        if not transactions:
            return

        unique_accounts = set()
        out_count = defaultdict(int)
        in_count = defaultdict(int)
        sent_vol = defaultdict(float)
        recv_vol = defaultdict(float)

        min_time = float('inf')
        max_time = float('-inf')
        post_breach_tx_count = 0

        for tx in transactions:
            if tx.timestamp < breach_time_minutes:
                continue

            post_breach_tx_count += 1
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
        print(f"NETWORK: {len(unique_accounts)} accounts, {post_breach_tx_count} post-breach transactions, time span {min_time}-{max_time} min")
        print(f"{'Account':<14} {'Out#':>5} {'In#':>5} {'Sent($)':>14} {'Received($)':>14}")

        for acc in sorted(unique_accounts):
            print(f"{acc:<14} {out_count[acc]:>5} {in_count[acc]:>5} {sent_vol[acc]:>14.2f} {recv_vol[acc]:>14.2f}")


# ==========================================
# 5. MAIN MENU SYSTEM
# ==========================================

# Time Complexity: O(1)
def convert_time_to_minutes(time_str):
    parts = time_str.strip().split(":")
    if len(parts) != 2:
        raise ValueError("Invalid format")
    hours = int(parts[0])
    minutes = int(parts[1])
    if not (0 <= hours <= 23 and 0 <= minutes <= 59):
        raise ValueError("Time out of range")
    return (hours * 60) + minutes


def main():
    master_transactions = []
    segment_tree = SegmentTree(0, 1440)
    global_graph = TemporalMultiGraph()
    tx_counter = 1

    while True:
        print("==================================================================================")
        print("                     SURVEILLANCE & FINANCIAL FRAUD ENGINE ")
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
                if len(parts) < 4:
                    print("   [!] Format Error! Expected: Sender Receiver Amount Timestamp(HH:mm)")
                    continue

                try:
                    sender = parts[0].lower()
                    receiver = parts[1].lower()
                    amount = float(parts[2])
                    time_str = parts[3]

                    timestamp_minutes = convert_time_to_minutes(time_str)
                    tx = Transaction(tx_counter, sender, receiver, amount, timestamp_minutes, time_str)
                    
                    master_transactions.append(tx)
                    segment_tree.insert(tx)
                    global_graph.add_edge(sender, receiver, amount, timestamp_minutes, time_str, tx.id)

                    print(f"   [+] Ingested: {tx}")
                    tx_counter += 1
                except Exception:
                    print("   [!] Parsing Error! Ensure Amount is numeric and Time is in HH:mm format (e.g. 08:35).")

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
            except Exception:
                print("[!] Invalid time format. Please use HH:mm between 00:00 and 23:59.\n")
                continue

            print("\n==================================================================================")
            print(f"          Complete Analysis (POST-BREACH TIME: {breach_time_str})")
            print("==================================================================================")

            breach_graph = TemporalMultiGraph()
            for tx in master_transactions:
                if tx.timestamp >= breach_time_minutes:
                    breach_graph.add_edge(tx.sender, tx.receiver, tx.amount, tx.timestamp, tx.original_time_str, tx.id)

            detector = FraudDetector()

            # 1. Tarjan's SCC Engine
            print("\n>>> [ENGINE 1] TARJAN'S SCC CYCLIC LAUNDERING ENGINE (POST-BREACH)")
            mule_rings = detector.find_mule_rings(breach_graph)

            if not mule_rings:
                print("    [STATUS: CLEAN] No circular mule rings identified post-breach.")
            else:
                for ring in mule_rings:
                    print("\n    [!] ALERT LEVEL: CRITICAL RISK")
                    print(f"        • Ring Entities      : {ring}")
                    print("        • Topology Pattern   : Closed Multi-Node Circular Loop")
                    print("        • Forensic Mechanism : Money is routed back to originating entities to artificially")
                    print("                               inflate trading volume and obscure true ownership.")
                    print("        • Compliance Action  : IMMEDIATE ACCOUNT FREEZE & SAR (Suspicious Activity Report) FILING.")

            # 2. Time-Constrained Velocity Engine
            print("\n>>> [ENGINE 2] TIME-CONSTRAINED VELOCITY & FLOW CONSERVATION ANALYSIS")
            reports = detector.analyze_advanced_money_trails(breach_graph, breach_time_minutes)

            if not reports:
                print("    [STATUS: CLEAN] No critical or needs monitoring pass-through chains detected.")
            else:
                for r in reports:
                    print(f"\n    [!] RISK ASSESSMENT: {r.risk_category}") 
                    print(f"        • Typology Tag   : {r.typology_tag}")
                    path_str = " --> ".join([f"{step.node} (Time={step.time_str})" for step in r.path])
                    print(f"        • Path Traversed : {path_str}")
                    print(f"        • Layer Count    : {len(r.path) - 1} intermediate hops")
                    print(f"        • Duration       : {r.total_duration} minutes post-breach")
                    print(f"        • Flow Conserved : {r.retention_ratio:.1f}% (${r.total_volume_in:.2f} In -> ${r.total_volume_out:.2f} Out)")
                    action = "Automated block on cashout node." if r.risk_category == "CRITICAL RISK" else "Flag for manual compliance review."
                    print(f"        • Action Required: {action}")

            # 3. Dynamic Network & Volume Summary Table
            print()
            detector.print_network_and_volume_summary(master_transactions, breach_time_minutes)

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