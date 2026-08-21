import asyncio
from datetime import datetime
import textwrap

from mock import ANY, AsyncMock, Mock, patch
import pytest

from middlewared.alert.source.ipmi_sel import (
    IPMISELRecord, IpmiTool, parse_ipmitool_output, parse_ipmi_sel_datetime, parse_sel_information,
    remove_deasserted_records,
    IPMISELAlertClass, IPMISELSpaceLeftAlertClass,
    IPMISELAlertSource, IPMISELSpaceLeftAlertSource,
    Alert
)


def test__parse_ipmitool_output():
    events = parse_ipmitool_output(textwrap.dedent("""\
        9,04/20/2017,06:03:07,Watchdog2 #0xca,Timer interrupt (),Asserted
        a,07/05/2017,03:17:30,Temperature PECI CPU1,Upper Non-critical going high,Asserted,Reading 144 > Threshold 81 degrees C
    """))

    assert events[0] == IPMISELRecord(
        id=9,
        datetime=datetime(2017, 4, 20, 6, 3, 7),
        sensor="Watchdog2 #0xca",
        event="Timer interrupt ()",
        direction="Asserted",
        verbose=None
    )

    assert events[1] == IPMISELRecord(
        id=10,
        datetime=datetime(2017, 7, 5, 3, 17, 30),
        sensor="Temperature PECI CPU1",
        event="Upper Non-critical going high",
        direction="Asserted",
        verbose="Reading 144 > Threshold 81 degrees C"
    )


def test__parse_ipmitool_output__ipmitool_1_8_19():
    # ipmitool 1.8.19 formats the date with strftime "%x" and the time with "%X %Z": the time carries
    # a zone name, and the year has four digits (en_US.UTF-8) or two (C locale, which is what the
    # alert source pins). 1.8.18 printed the bare "MM/DD/YYYY" / "HH:MM:SS" shape above.
    events = parse_ipmitool_output(textwrap.dedent("""\
        1ce,07/15/2026,21:02:53 CEST,Battery CMOS Battery,Failed,Deasserted
        1ff,08/15/26,23:45:40 UTC,Power Supply Status,Power Supply AC lost,Asserted
        200,08/16/26,01:45:40 CEST,Memory Mem ECC Warning,Transition to Critical from less severe,Asserted,Verbose text
    """))

    assert events == [
        IPMISELRecord(
            id=0x1ce,
            datetime=datetime(2026, 7, 15, 21, 2, 53),
            sensor="Battery CMOS Battery",
            event="Failed",
            direction="Deasserted",
            verbose=None,
        ),
        IPMISELRecord(
            id=0x1ff,
            datetime=datetime(2026, 8, 15, 23, 45, 40),
            sensor="Power Supply Status",
            event="Power Supply AC lost",
            direction="Asserted",
            verbose=None,
        ),
        IPMISELRecord(
            id=0x200,
            datetime=datetime(2026, 8, 16, 1, 45, 40),
            sensor="Memory Mem ECC Warning",
            event="Transition to Critical from less severe",
            direction="Asserted",
            verbose="Verbose text",
        ),
    ]


def test__parse_ipmitool_output__skips_malformed_rows():
    events = parse_ipmitool_output(textwrap.dedent("""\
        1,Pre-Init,0000000001,Event Logging Disabled SEL,Log area reset/cleared,Asserted
        2,not a date,23:45:40 UTC,Power Supply Status,Power Supply AC lost,Asserted
        3,08/15/2026,23:45:41 UTC,Power Supply Status,Power Supply AC lost,Deasserted
    """))

    assert [e.id for e in events] == [3]


@pytest.mark.parametrize("date,time,result", [
    ("08/15/2026", "23:45:40", datetime(2026, 8, 15, 23, 45, 40)),
    ("08/15/2026", "23:45:40 UTC", datetime(2026, 8, 15, 23, 45, 40)),
    ("08/15/26", "23:45:40 UTC", datetime(2026, 8, 15, 23, 45, 40)),
    ("08/16/2026", "01:45:40 CEST", datetime(2026, 8, 16, 1, 45, 40)),
    (" 08/15/2026", " 23:45:40 UTC", datetime(2026, 8, 15, 23, 45, 40)),
])
def test__parse_ipmi_sel_datetime(date, time, result):
    assert parse_ipmi_sel_datetime(date, time) == result


@pytest.mark.parametrize("date,time", [
    ("15/08/2026", "23:45:40 UTC"),
    ("08/15/2026", "23:45"),
    ("Pre-Init", "0000000001"),
])
def test__parse_ipmi_sel_datetime__rejects(date, time):
    with pytest.raises(ValueError):
        parse_ipmi_sel_datetime(date, time)


@pytest.mark.asyncio
async def test_ipmi_sel_alert_source__runs_ipmitool_in_utc():
    middleware = Mock()
    middleware.run_in_thread = AsyncMock(return_value=True)

    source = IPMISELAlertSource(middleware)
    source._produce_alerts_for_ipmitool_output = AsyncMock(return_value=[])

    with patch("middlewared.alert.source.ipmi_sel.ipmitool", AsyncMock(return_value="")) as ipmitool:
        await source.check()

    ipmitool.assert_called_once_with(["-Z", "-c", "sel", "elist"])


@pytest.mark.asyncio
async def test_ipmitool__pins_the_locale():
    with patch("middlewared.alert.source.ipmi_sel.run", AsyncMock(return_value=Mock(returncode=0, stdout=""))) as run:
        await IpmiTool()(["-Z", "-c", "sel", "elist"])

    assert run.call_args.args[0] == ["ipmitool", "-Z", "-c", "sel", "elist"]
    assert run.call_args.kwargs["env"]["LC_ALL"] == "C"


def test__parse_sel_information():
    info = parse_sel_information(textwrap.dedent("""\
        SEL Information
        Version          : 1.5 (v1.5, v2 compliant)
        Entries          : 19
        Free Space       : 9860 bytes
        Percent Used     : 2%
        Last Add Time    : 07/05/2018 23:32:08
        Last Del Time    : Not Available
        Overflow         : false
        Supported Cmds   : 'Reserve' 'Get Alloc Info'
        # of Alloc Units : 512
        Alloc Unit Size  : 20
        # Free Units     : 493
        Largest Free Blk : 493
        Max Record Size  : 20
    """))

    assert info["Free Space"] == "9860 bytes"
    assert info["Percent Used"] == "2%"


@pytest.mark.asyncio
async def test_ipmi_sel_alert_source__works():
    middleware = Mock()
    fut1 = asyncio.Future()
    fut1.set_result(True)
    fut2 = asyncio.Future()
    fut2.set_result(datetime.min)
    middleware.call = lambda method, *args: ({
        "keyvalue.has_key": fut1,
        "keyvalue.get": fut2,
    }[method])

    source = IPMISELAlertSource(middleware)

    assert await source._produce_alerts_for_ipmitool_output(textwrap.dedent("""\
        26,09/15/2022,15:34:46,Voltage PVPP,Lower Non-recoverable going low,Asserted,Reading 0.12 < Threshold 2.17 Volts
    """)) == [
        Alert(
            IPMISELAlertClass,
            args=dict(
                sensor="Voltage PVPP",
                event="Lower Non-recoverable going low",
                direction="Asserted",
                verbose="Reading 0.12 < Threshold 2.17 Volts"
            ),
            _key=ANY,
            datetime=datetime(2022, 9, 15, 15, 34, 46),
        )
    ]


@pytest.mark.asyncio
async def test_ipmi_sel_alert_source__works_filters_dismissed_events():
    middleware = Mock()
    fut1 = asyncio.Future()
    fut1.set_result(True)
    fut2 = asyncio.Future()
    fut2.set_result(datetime(2017, 4, 20, 6, 3, 7))
    middleware.call = lambda method, *args: ({
        "keyvalue.has_key": fut1,
        "keyvalue.get": fut2,
    }[method])

    source = IPMISELAlertSource(middleware)

    assert await source._produce_alerts_for_ipmitool_output(textwrap.dedent("""\
        9,04/20/2017,06:03:07,Power Unit #0xca,Failure detected,Asserted
        9,04/20/2017,06:03:08,Power Unit #0xca,Failure detected,Asserted
    """)) == [
        Alert(
            IPMISELAlertClass,
            args=dict(
                sensor="Power Unit #0xca",
                event="Failure detected",
                direction="Asserted",
                verbose=None
            ),
            _key=ANY,
            datetime=datetime(2017, 4, 20, 6, 3, 8),
        )
    ]


@pytest.mark.asyncio
async def test_ipmi_sel_alert_source__first_run():
    def _create_future(m, *args):
        fut = asyncio.Future()
        fut.set_result(m(*args))
        return fut
    m2 = Mock()
    middleware = Mock()
    middleware.call = lambda method, *args: ({
        "keyvalue.has_key": lambda *args: _create_future(Mock(return_value=False), *args),
        "keyvalue.set": lambda *args: _create_future(m2, *args),
    }[method](*args))

    source = IPMISELAlertSource(middleware)

    assert await source._produce_alerts_for_ipmitool_output(textwrap.dedent("""\
        9,04/20/2017,06:03:07,Power Unit #0xca,Failure detected,Asserted
    """)) == []

    m2.assert_called_once_with("alert:ipmi_sel:dismissed_datetime", datetime(2017, 4, 20, 6, 3, 7))


def test_ipmi_sel_space_left_alert_source__does_not_emit():
    assert IPMISELSpaceLeftAlertSource(None)._produce_alert_for_ipmitool_output(textwrap.dedent("""\
        SEL Information
        Version          : 1.5 (v1.5, v2 compliant)
        Entries          : 19
        Free Space       : 9860 bytes
        Percent Used     : 2%
        Last Add Time    : 07/05/2018 23:32:08
        Last Del Time    : Not Available
        Overflow         : false
        Supported Cmds   : 'Reserve' 'Get Alloc Info'
        # of Alloc Units : 512
        Alloc Unit Size  : 20
        # Free Units     : 493
        Largest Free Blk : 493
        Max Record Size  : 20
    """)) is None


def test_ipmi_sel_space_left_alert_source__emits():
    assert IPMISELSpaceLeftAlertSource(None)._produce_alert_for_ipmitool_output(textwrap.dedent("""\
        SEL Information
        Version          : 1.5 (v1.5, v2 compliant)
        Entries          : 19
        Free Space       : 260 bytes
        Percent Used     : 98%
        Last Add Time    : 07/05/2018 23:32:08
        Last Del Time    : Not Available
        Overflow         : false
        Supported Cmds   : 'Reserve' 'Get Alloc Info'
        # of Alloc Units : 512
        Alloc Unit Size  : 20
        # Free Units     : 493
        Largest Free Blk : 493
        Max Record Size  : 20
    """)) == Alert(
        IPMISELSpaceLeftAlertClass,
        args={
            "free": "260 bytes",
            "used": "98%",
        },
        key=None,
    )


@pytest.mark.parametrize("records,result", [
    (
        [
            IPMISELRecord(
                id=9,
                datetime=datetime(2017, 4, 20, 6, 3, 7),
                sensor="PS2 Status",
                event="Power Supply Failure detected",
                direction="Asserted",
                verbose=None,
            ),
            IPMISELRecord(
                id=10,
                datetime=datetime(2017, 4, 20, 6, 3, 8),
                sensor="PS2 Status",
                event="Power Supply Failure detected",
                direction="Deasserted",
                verbose=None,
            ),
            IPMISELRecord(
                id=11,
                datetime=datetime(2017, 4, 20, 6, 3, 9),
                sensor="Sensor #255",
                event="Event Offset = 00h",
                direction="Asserted",
                verbose=None,
            ),
        ],
        [2],
    )
])
def test_remove_deasserted_records(records, result):
    assert remove_deasserted_records(records) == [records[i] for i in result]
