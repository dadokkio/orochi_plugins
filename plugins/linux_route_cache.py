# Volatility 3 plugin: Linux RouteCache (IPv4 FIB Routing Table)
# Walks init_net.ipv4.fib_table_hash and its FIB trie (key_vector) to extract IPv4 routes.

import logging
import socket
import struct
from typing import Iterable, List, Set, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)

RTN_TYPES = {
    0: "UNSPEC",
    1: "UNICAST",
    2: "LOCAL",
    3: "BROADCAST",
    4: "ANYCAST",
    5: "MULTICAST",
    6: "BLACKHOLE",
    7: "UNREACHABLE",
    8: "PROHIBIT",
    9: "THROW",
    10: "NAT",
}

RT_SCOPES = {
    0: "UNIVERSE",
    200: "SITE",
    253: "LINK",
    254: "HOST",
    255: "NOWHERE",
}

TABLE_NAMES = {
    253: "default",
    254: "main",
    255: "local",
}


def _ipv4_from_be32(val: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", val & 0xFFFFFFFF))


def _ipv4_from_le32(val: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", val & 0xFFFFFFFF))


class RouteCache(interfaces.plugins.PluginInterface):
    """Extracts IPv4 routing table entries from Linux kernel FIB trie (init_net)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _extract_fib_info(self, fa) -> Tuple[str, str, int]:
        gw = "0.0.0.0"
        dev_name = "-"
        scope = 0
        try:
            fi = fa.fa_info.dereference()
            if fi.has_member("fib_scope"):
                scope = int(fi.fib_scope)
            if fi.has_member("fib_nh"):
                nh = fi.fib_nh[0]
                if nh.has_member("nh_gw"):
                    gw = _ipv4_from_le32(int(nh.nh_gw))
                elif nh.has_member("nh_common") and nh.nh_common.has_member("nhc_gw"):
                    gw = _ipv4_from_le32(int(nh.nh_common.nhc_gw.ipv4))
                if nh.has_member("nh_dev") and int(nh.nh_dev):
                    dev_name = utility.array_to_string(nh.nh_dev.dereference().name) or "-"
                elif nh.has_member("nh_common") and nh.nh_common.has_member("nhc_dev") and int(nh.nh_common.nhc_dev):
                    dev_name = utility.array_to_string(nh.nh_common.nhc_dev.dereference().name) or "-"
        except (AttributeError, IndexError, exceptions.InvalidAddressException):
            pass
        return gw, dev_name, scope

    def _walk_key_vector(
        self,
        kernel,
        kv,
        table_label: str,
        seen: Set[int],
        depth: int = 0,
    ) -> Iterable[Tuple[int, Tuple]]:
        if depth > 64:
            return
        kv_off = int(kv.vol.offset)
        if kv_off in seen:
            return
        seen.add(kv_off)

        try:
            bits = int(kv.bits)
            key = int(kv.key)
            slen = int(kv.slen) if kv.has_member("slen") else 0
        except exceptions.InvalidAddressException:
            return

        # Leaf node (bits == 0) holds fib_alias list
        if bits == 0:
            dest_ip = _ipv4_from_be32(key)
            if kv.has_member("leaf"):
                try:
                    head = kv.leaf
                    node = head.first if head.has_member("first") else None
                    guard = 0
                    while node and int(node) and guard < 64:
                        guard += 1
                        fa = kernel.object(
                            object_type="fib_alias",
                            offset=int(node) - kernel.get_type("fib_alias").relative_child_offset("fa_list"),
                            absolute=True,
                        )
                        fa_type = int(fa.fa_type) if fa.has_member("fa_type") else 0
                        prefix_len = max(0, 32 - int(fa.fa_slen)) if fa.has_member("fa_slen") else max(0, 32 - slen)
                        gw, dev_name, scope = self._extract_fib_info(fa)
                        yield (
                            0,
                            (
                                table_label,
                                dest_ip,
                                prefix_len,
                                gw,
                                dev_name,
                                RTN_TYPES.get(fa_type, str(fa_type)),
                                RT_SCOPES.get(scope, str(scope)),
                            ),
                        )
                        node = node.dereference().next if node.dereference().has_member("next") else None
                except (AttributeError, exceptions.InvalidAddressException, exceptions.SymbolError):
                    pass
            return

        # Internal tnode: iterate 1 << bits child pointers
        if bits > 16 or not kv.has_member("tnode"):
            return
        n_children = 1 << bits
        ptr_size = kernel.get_type("pointer").size
        base_off = kv.tnode.vol.offset

        for i in range(n_children):
            try:
                child_ptr = int(
                    kernel.object(object_type="pointer", offset=base_off + i * ptr_size, absolute=True)
                )
            except exceptions.InvalidAddressException:
                continue
            if not child_ptr or child_ptr in seen:
                continue
            try:
                child_kv = kernel.object(object_type="key_vector", offset=child_ptr, absolute=True)
                yield from self._walk_key_vector(kernel, child_kv, table_label, seen, depth + 1)
            except (exceptions.InvalidAddressException, exceptions.SymbolError):
                continue

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        kernel = self.context.modules[self.config["kernel"]]
        if not kernel.has_symbol("init_net"):
            vollog.warning("Symbol 'init_net' not found.")
            return

        try:
            init_net = kernel.object_from_symbol("init_net")
            fib_hash_ptr = int(init_net.ipv4.fib_table_hash)
        except (AttributeError, exceptions.InvalidAddressException) as excp:
            vollog.debug(f"Unable to read init_net.ipv4.fib_table_hash: {excp}")
            return

        if not fib_hash_ptr:
            return

        hlist_head_size = kernel.get_type("hlist_head").size
        tb_hlist_off = kernel.get_type("fib_table").relative_child_offset("tb_hlist")
        seen_tables: Set[int] = set()

        # FIB_TABLE_HASHSZ is 256 in modern Linux kernels (2 on tiny configs)
        for bucket in range(256):
            try:
                head = kernel.object(
                    object_type="hlist_head",
                    offset=fib_hash_ptr + bucket * hlist_head_size,
                    absolute=True,
                )
                node_ptr = int(head.first)
            except exceptions.InvalidAddressException:
                break

            guard = 0
            while node_ptr and node_ptr not in seen_tables and guard < 64:
                seen_tables.add(node_ptr)
                guard += 1
                try:
                    tb = kernel.object(
                        object_type="fib_table",
                        offset=node_ptr - tb_hlist_off,
                        absolute=True,
                    )
                    tb_id = int(tb.tb_id)
                    tb_label = TABLE_NAMES.get(tb_id, str(tb_id))
                    trie_off = tb.tb_data.vol.offset
                    trie = kernel.object(object_type="trie", offset=trie_off, absolute=True)
                    if trie.has_member("kv"):
                        root_kv = trie.kv[0]
                        yield from self._walk_key_vector(kernel, root_kv, tb_label, set())
                    node_ptr = int(tb.tb_hlist.next)
                except (AttributeError, exceptions.InvalidAddressException, exceptions.SymbolError):
                    break

    def run(self):
        return renderers.TreeGrid(
            [
                ("Table", str),
                ("Destination", str),
                ("PrefixLen", int),
                ("Gateway", str),
                ("Interface", str),
                ("Type", str),
                ("Scope", str),
            ],
            self._generator(),
        )
