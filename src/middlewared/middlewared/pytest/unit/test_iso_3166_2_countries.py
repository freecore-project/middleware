import csv
import unicodedata
from pathlib import Path

COUNTRIES = Path(__file__).resolve().parents[5] / 'src/freenas/etc/iso_3166_2_countries.csv'


def test__country_names_have_no_control_characters():
    # `system.general.country_choices` uses the Common Name column as the label as is
    with open(COUNTRIES, encoding='utf-8', newline='') as f:
        for row in csv.DictReader(f):
            name = row['Common Name']
            assert not any(unicodedata.category(c) == 'Cc' for c in name), repr(name)
