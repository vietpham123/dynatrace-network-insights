from setuptools import setup, find_packages

# pysnmp is the ONLY third-party dependency, and it is pinned. Both it and its transitive
# dependency pyasn1 ship as py3-none-any (universal, pure-Python) wheels — checked, not
# assumed — so this extension carries no compiled artifacts and survives the Python 3.10 ->
# 3.14 runtime move untouched. That property is worth preserving: see
# docs/ENTERPRISE-READINESS.md §M before adding any dependency here.
#
# On the package identity: after the original author died in 2022 the maintained fork
# (lextudio) became `pysnmp` on PyPI again, and 7.x is that line. The older `pysnmplib` /
# `pysnmp-lextudio` names are dead ends — do not "fix" this to one of those.
#
# dt-extensions-sdk MUST be listed: it is NOT provided by the EEC runtime. Proven on a
# real ActiveGate 2026-08-01 - without it the extension dies at import with
# 'ModuleNotFoundError: No module named dynatrace_extension'.
setup(
    name="controlplane_extension",
    version="0.0.1",
    description="CNO LLDP topology extension — neighbour discovery with correct binary TLV decoding",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["dt-extensions-sdk", "pysnmp==7.1.28"],
)
