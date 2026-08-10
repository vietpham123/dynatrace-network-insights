from setuptools import setup, find_packages

# stdlib-only (glob/os/re/subprocess). Drift uses the system `git` binary on the AG (not a pip dep).
# dt-extensions-sdk MUST be a dependency: it is NOT provided by the EEC runtime.
# Proven on a real ActiveGate 2026-08-01 - without it the extension dies at import with
# 'ModuleNotFoundError: No module named dynatrace_extension'. The SDK's own scaffold
# (dt-sdk create) lists it too. This was wrong in every extension here until a Python
# extension was deployed to an AG for the first time (see ENTERPRISE-READINESS.md SS D/N).
setup(
    name="oxidized_extension",
    version="0.0.1",
    description="CNO Oxidized/Git -> Dynatrace compliance + config-change extension",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["dt-extensions-sdk"],
)
