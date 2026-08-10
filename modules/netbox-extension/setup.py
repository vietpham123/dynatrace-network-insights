from setuptools import setup, find_packages

# stdlib-only extension (urllib/json). dynatrace_extension is provided by the EEC runtime,
# so it is not listed here. dt-sdk build bundles this package into the signed .zip.
setup(
    name="netbox_extension",
    version="0.0.1",
    description="CNO NetBox -> Dynatrace source extension",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["dt-extensions-sdk"],
)
