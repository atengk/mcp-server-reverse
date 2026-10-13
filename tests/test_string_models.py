"""字符串与密码学特征数据模型单元测试套件

@author Ateng
@since 2026-10-13
"""

from mcp_server_reverse.core.models import CryptoSignature, StringArtifact


def test_string_artifact_model() -> None:
    artifact = StringArtifact(
        value="https://api.example.com",
        encoding="ascii",
        file_offset=0x2250,
        virtual_address="0x140002250",
        section=".rdata",
        ioc_category="url",
        length=23,
    )
    d = artifact.to_dict()
    assert d["value"] == "https://api.example.com"
    assert d["encoding"] == "ascii"
    assert d["file_offset"] == 0x2250
    assert d["virtual_address"] == "0x140002250"
    assert d["section"] == ".rdata"
    assert d["ioc_category"] == "url"
    assert d["length"] == 23


def test_crypto_signature_model() -> None:
    sig = CryptoSignature(
        algorithm="AES",
        name="AES S-Box",
        virtual_address="0x140002300",
        file_offset=0x2300,
        section=".rdata",
        confidence=1.0,
    )
    d = sig.to_dict()
    assert d["algorithm"] == "AES"
    assert d["name"] == "AES S-Box"
    assert d["virtual_address"] == "0x140002300"
    assert d["file_offset"] == 0x2300
    assert d["confidence"] == 1.0
