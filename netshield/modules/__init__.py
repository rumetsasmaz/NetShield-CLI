"""Module registry. To add a tool: write a BaseModule subclass and list it here."""

from netshield.modules.hashing import HashCrackerModule, HashModule
from netshield.modules.password import PasswordCheckerModule, PasswordGeneratorModule
from netshield.modules.portdb import PortDatabaseModule
from netshield.modules.scanner import HostDiscoveryModule, PortScannerModule
from netshield.modules.settings import ThemeModule
from netshield.modules.sniffer import PacketSnifferModule

ALL_MODULES = [
    PortScannerModule(),
    HostDiscoveryModule(),
    PacketSnifferModule(),
    PortDatabaseModule(),
    PasswordCheckerModule(),
    PasswordGeneratorModule(),
    HashModule(),
    HashCrackerModule(),
    ThemeModule(),
]
