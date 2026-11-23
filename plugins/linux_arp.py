# Volatility 3 plugin: Linux ARP cache
# Extracts IPv4 neighbor / ARP table entries from the kernel's arp_tbl (struct neigh_table).

import logging
import socket
from typing import Iterable, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

# Linux include/uapi/linux/neighbour.h NUD_* state bitmask
NUD_STATES = (
    (0x01, "INCOMPLETE"),
    (0x02, "REACHABLE"),
    (0x04, "STALE"),
    (0x08, "DELAY"),
    (0x10, "PROBE"),
    (0x20, "FAILED"),
    (0x40, "NOARP"),
    (0x80, "PERMANENT"),
)


def _decode_nud_state(state: int) -> str:
    flags = [name for bit, name in NUD_STATES if state & bit]
    return "|".join(flags) if flags else f"NONE(0x{state:02x})"


def _format_mac(raw: bytes) -> str:
    if len(raw) < 6:
        return "-"
    return ":".join(f"{b:02x}" for b in raw[:6])


class Arp(interfaces.plugins.PluginInterface):
    """Prints the Linux kernel ARP / neighbor table from arp_tbl."""

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

    @staticmethod
    def _get_bucket_count(nht) -> int:
        if nht.has_member("hash_shift"):
            shift = int(nht.hash_shift)
            if 0 <= shift <= 20:
                return 1 << shift
        if nht.has_member("hash_mask"):
            mask = int(nht.hash_mask)
            if 0 <= mask < (1 << 20):
                return mask + 1
        return 0

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]

        if not kernel.has_symbol("arp_tbl"):
            vollog.warning("Kernel symbol 'arp_tbl' not found in symbol table.")
            return

        try:
            arp_tbl = kernel.object_from_symbol("arp_tbl")
            nht = arp_tbl.nht.dereference()
        except exceptions.InvalidAddressException as excp:
            vollog.debug(f"Unable to dereference arp_tbl.nht: {excp}")
            return

        num_buckets = self._get_bucket_count(nht)
        if num_buckets <= 0:
            vollog.warning("Unable to determine ARP hash bucket count.")
            return

        ptr_type = kernel.get_type("pointer")
        ptr_size = ptr_type.size
        buckets_base = int(nht.hash_buckets)
        seen_addrs = set()

        for idx in range(num_buckets):
            try:
                bucket_ptr_obj = kernel.object(
                    object_type="pointer",
                    offset=buckets_base + idx * ptr_size,
                    absolute=True,
                )
                neigh_addr = int(bucket_ptr_obj)
            except exceptions.InvalidAddressException:
                continue

            depth = 0
            while neigh_addr and neigh_addr not in seen_addrs and depth < 1024:
                seen_addrs.add(neigh_addr)
                depth += 1
                try:
                    neigh = kernel.object(
                        object_type="neighbour",
                        offset=neigh_addr,
                        absolute=True,
                    )
                except exceptions.InvalidAddressException:
                    break

                # IPv4 address from primary_key (first 4 bytes)
                try:
                    pk_off = neigh.primary_key.vol.offset
                    ip_bytes = kernel_layer.read(pk_off, 4, pad=False)
                    ip_str = socket.inet_ntoa(ip_bytes)
                except Exception:
                    ip_str = "-"

                # Hardware (MAC) address from ha (first 6 bytes)
                try:
                    ha_off = neigh.ha.vol.offset
                    ha_bytes = kernel_layer.read(ha_off, 6, pad=False)
                    mac_str = _format_mac(ha_bytes)
                except Exception:
                    mac_str = "-"

                # Network device name
                dev_name = "-"
                try:
                    if int(neigh.dev):
                        dev = neigh.dev.dereference()
                        dev_name = utility.array_to_string(dev.name) or "-"
                except Exception:
                    pass

                # Neighbor Unreachability Detection state
                try:
                    nud_state = _decode_nud_state(int(neigh.nud_state))
                except Exception:
                    nud_state = "-"

                yield (
                    0,
                    (
                        ip_str,
                        mac_str,
                        dev_name,
                        nud_state,
                        format_hints.Hex(neigh_addr),
                    ),
                )

                try:
                    neigh_addr = int(neigh.next)
                except exceptions.InvalidAddressException:
                    break

    def run(self):
        return renderers.TreeGrid(
            [
                ("IP Address", str),
                ("MAC Address", str),
                ("Interface", str),
                ("State", str),
                ("Offset", format_hints.Hex),
            ],
            self._generator(),
        )
