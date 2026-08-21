import pytest

from middlewared.schema import Int, Str
from middlewared.validators import Email, Hostname, Match, Range, validate_attributes


@pytest.mark.parametrize("email,should_raise", [
    ("2@2@me.com", False),
    ("2&2@me.com", False),
    ("2@\uD800\uD800ñoñó郵件ñoñó郵件.商務", False),
    (f'{"2" * 250}@me.com', True),
    ("@me.com", True),
    ("2@", True),
    ("@", True),
    ("", True),
])
def test__email_schema(email, should_raise):
    if not should_raise:
        Email()(email)
    else:
        with pytest.raises(ValueError):
            Email()(email)


@pytest.mark.parametrize("validator,value,should_raise", [
    (Match(r"^[0-7]{3}$"), "027", False),
    (Match(r"^[0-7]{3}$"), "027\n", True),
    (Match(r"^[0-7]{3}$"), "0277", True),
    (Hostname(), "nas", False),
    (Hostname(), "nas\n", True),
    # a newline the pattern itself allows is still accepted
    (Match(r"^[-_.a-zA-Z0-9\s]*$"), "public\n", False),
    # an unanchored pattern only has to match a prefix
    (Match(r"[^/\]]"), "module", False),
    (Match(r".*:.*"), "tank:disk", False),
])
def test__match(validator, value, should_raise):
    if not should_raise:
        validator(value)
    else:
        with pytest.raises(ValueError):
            validator(value)


def test__email_schema_max_length_message():
    with pytest.raises(ValueError, match=r"^Maximum length is 254 characters\.$"):
        Email()(f'{"2" * 250}@me.com')


@pytest.mark.parametrize("attributes,error", [
    ({"email": ["root@localhost"]}, ("email", "Not a string")),
    ({"chunk_size": 1}, ("chunk_size", "Should be greater or equal than 5")),
    ({"email": "x" * 1025}, ("email", "Value greater than 1024 not allowed")),
], ids=["rejected-by-clean", "rejected-by-validator", "rejected-by-max-length"])
def test__validate_attributes_error_names(attributes, error):
    # Callers prefix these with `<schema>.attributes`, so both steps must name the bare key
    verrors = validate_attributes([Str("email"), Int("chunk_size", validators=[Range(min=5)])],
                                  {"attributes": attributes})

    assert [(e.attribute, e.errmsg) for e in verrors.errors] == [error]
