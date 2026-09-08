from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous.encoding import base64_encode
from itsdangerous.encoding import int_to_bytes
from itsdangerous.exc import BadSignature
from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_signer import TestSigner


class FreezeMixin:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft


class TestTimestampSigner(FreezeMixin, TestSigner):
    @pytest.fixture()
    def signer_factory(self):
        return partial(TimestampSigner, secret_key="secret-key")

    def test_max_age(self, signer, ts, freeze):
        signed = signer.sign("value")
        freeze.tick()
        assert signer.unsign(signed, max_age=10) == b"value"
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            signer.unsign(signed, max_age=10)

        assert exc_info.value.date_signed == ts

    def test_return_timestamp(self, signer, ts):
        signed = signer.sign("value")
        assert signer.unsign(signed, return_timestamp=True) == (b"value", ts)

    def test_timestamp_missing(self, signer):
        other = Signer("secret-key")
        signed = other.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "missing" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_timestamp(self, signer):
        other = Signer("secret-key")
        signed = other.sign(b"value.____________")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_future_timestamp(self, signer):
        signed = b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY"

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_future_age(self, signer):
        signed = signer.sign("value")

        with freeze_time("1971-05-31"):
            with pytest.raises(SignatureExpired) as exc_info:
                signer.unsign(signed, max_age=10)

        assert isinstance(exc_info.value.date_signed, datetime)

    def test_sig_error_date_signed(self, signer):
        signed = signer.sign("my string").replace(b"my", b"other", 1)

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert isinstance(exc_info.value.date_signed, datetime)

    def test_split_timestamp_reraises_sig_error(self, signer):
        sig_error = BadSignature("bad signature", payload=b"novalidsep")

        with pytest.raises(BadSignature) as exc_info:
            signer._split_timestamp(b"novalidsep", sig_error)

        assert exc_info.value is sig_error

    def test_split_timestamp_missing_without_sig_error(self, signer):
        with pytest.raises(BadTimeSignature) as exc_info:
            signer._split_timestamp(b"novalidsep", None)

        assert "missing" in str(exc_info.value)

    def test_split_timestamp_success(self, signer):
        value, ts_bytes = signer._split_timestamp(b"value.abc123", None)
        assert value == b"value"
        assert ts_bytes == b"abc123"

    def test_parse_timestamp_valid(self, signer):
        ts_bytes = base64_encode(int_to_bytes(1234))
        assert signer._parse_timestamp(ts_bytes) == 1234

    def test_parse_timestamp_malformed(self, signer):
        assert signer._parse_timestamp(b"____________") is None

    def test_check_max_age_expired(self, signer, ts):
        with pytest.raises(SignatureExpired) as exc_info:
            signer._check_max_age(b"value", int(ts.timestamp()) - 20, 10)

        assert "seconds" in str(exc_info.value)
        assert exc_info.value.date_signed == ts - timedelta(seconds=20)

    def test_check_max_age_in_future(self, signer, ts):
        with pytest.raises(SignatureExpired) as exc_info:
            signer._check_max_age(b"value", int(ts.timestamp()) + 20, 10)

        assert "seconds" in str(exc_info.value)

    def test_check_max_age_within_bounds(self, signer, ts):
        # Should not raise when the timestamp is within max_age.
        signer._check_max_age(b"value", int(ts.timestamp()), 10)

    def test_raise_for_sig_error_with_valid_timestamp(self, signer, ts):
        sig_error = BadSignature("bad signature")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer._raise_for_sig_error(sig_error, b"value", int(ts.timestamp()))

        assert exc_info.value.date_signed == ts

    def test_raise_for_sig_error_without_timestamp(self, signer):
        sig_error = BadSignature("bad signature")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer._raise_for_sig_error(sig_error, b"value", None)

        assert exc_info.value.date_signed is None


class TestTimedSerializer(FreezeMixin, TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(TimedSerializer, secret_key="secret_key")

    def test_max_age(self, serializer, value, ts, freeze):
        signed = serializer.dumps(value)
        freeze.tick()
        assert serializer.loads(signed, max_age=10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            serializer.loads(signed, max_age=10)

        assert exc_info.value.date_signed == ts
        assert serializer.load_payload(exc_info.value.payload) == value

    def test_return_payload(self, serializer, value, ts):
        signed = serializer.dumps(value)
        assert serializer.loads(signed, return_timestamp=True) == (value, ts)
