"""Module registry. To add a tool: write a BaseModule subclass and list it here."""

from netshield.modules.analyzer import PcapAnalyzerModule
from netshield.modules.hashing import HashCrackerModule, HashModule
from netshield.modules.headers import HttpHeadersModule
from netshield.modules.password import PasswordCheckerModule, PasswordGeneratorModule
from netshield.modules.portdb import PortDatabaseModule
from netshield.modules.scanner import HostDiscoveryModule, PortScannerModule, TlsCheckModule
from netshield.modules.settings import ThemeModule
from netshield.modules.sniffer import PacketSnifferModule

ALL_MODULES = [
    PortScannerModule(),
    HostDiscoveryModule(),
    TlsCheckModule(),
    HttpHeadersModule(),
    PacketSnifferModule(),
    PcapAnalyzerModule(),
    PortDatabaseModule(),
    PasswordCheckerModule(),
    PasswordGeneratorModule(),
    HashModule(),
    HashCrackerModule(),
    ThemeModule(),
]
