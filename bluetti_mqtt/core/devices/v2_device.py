from typing import List
from ..commands import ReadHoldingRegisters
from .bluetti_device import BluettiDevice
from .struct import DeviceStruct
from enum import Enum, Flag, unique


@unique
class ProtocolAddress(Enum):
    BASE_CONFIG = 1
    HOME_DATA = 100
    OTA_STATUS = 720
    INV_BASE_INFO = 1100
    INV_PV_INFO = 1200
    INV_GRID_INFO = 1300
    INV_LOAD_INFO = 1400
    INV_INVERTER_INFO = 1500
    INV_BASE_SETTINGS_INFO = 2000
    AC_SWITCH = 2011  # Writable, 1 = on, 0 = off
    DC_SWITCH = 2012  # Writable, 1 = on, 0 = off
    INV_ADVANCED_SETTINGS_INFO = 2200
    CERT_SETTINGS_INFO = 2400
    MICRO_INV_ADV_SETTINGS = 2500
    FAULT_HISTORY_DATA = 3000
    TOTAL_ENERGY_INFO = 3500
    INV_CURR_YEAR_ENERGY = 3600
    TIME_CTRL_INFO = 5000
    PACK_MAIN_INFO = 6000
    PACK_ITEM_INFO = 6100
    PACK_SUB_PACK_INFO = 6300  # PACK_CELLS_INFO_SPLIT_START
    PACK_SETTING = 7000        # PACK_CELLS_INFO_SPLIT_END
    PACK_BMU_INFO = 7200
    IOT_BASE_INFO = 11000
    IOT_SETTINGS_INFO = 12002
    IOT_ENABLE_INFO = 12161
    DISASTER_WARNING_MODE = 12163
    IOT_WIFI_MESH = 13500
    HMI_INFO = 14000
    SMART_PLUG_INFO = 14500
    SMART_PLUG_SETTINGS = 14700
    CHARGING_PILE_INFO = 15000
    CHARGER_INFO = 15500
    CHARGER_SETTINGS = 15600
    DC_HUB_INFO = 15700
    DC_HUB_SETTINGS = 15750
    ATS_INFO = 17000
    NODE_INFO = 21000
    COMM_DATA_OTHER = 40000


@unique
class CtrlStatusMask(Flag):
    POWER_ENABLE = 1 << 0
    AC_ENABLE = 1 << 1
    DC_ENABLE = 1 << 2
    INV_ENABLE = 1 << 3
    GRID_ENABLE = 1 << 4
    PV_ENABLE = 1 << 5
    FEEDBACK_ENABLE = 1 << 6
    METER_ENABLE = 1 << 7
    LED_ENABLE = 1 << 8
    ECO_ENABLE = 1 << 9
    SUPER_POWER_ENABLE = 1 << 10


@unique
class ChargingMode(Enum):
    STANDARD = 0
    SILENT = 1
    TURBO = 2


class V2Device(BluettiDevice):
    def __init__(self, address: str, sn: str, type: str):
        super().__init__(address, type, sn)
        self.struct = DeviceStruct(chunk_size=1)

        # Setters
        # See ctrl_status to read the current value of these two (it's a bitfield)
        self.struct.add_bool_field("ac_switch", ProtocolAddress.AC_SWITCH.value)
        self.struct.add_bool_field("dc_switch", ProtocolAddress.DC_SWITCH.value)

        # BaseConfig
        self.struct.add_uint8_field("cfg_specs", ProtocolAddress.BASE_CONFIG.value + 0)
        self.struct.add_uint8_field("cfg_voltage_type", ProtocolAddress.BASE_CONFIG.value + 1)
        self.struct.add_uint_field("cfg_guest_mode_enabled", ProtocolAddress.BASE_CONFIG.value + 2)
        self.struct.add_uint_field("cfg_bt_psw_enabled", ProtocolAddress.BASE_CONFIG.value + 10)
        self.struct.add_swap_string_field("cfg_bt_password", ProtocolAddress.BASE_CONFIG.value + 12, 9)
        self.struct.add_uint_field("cfg_modbus_version", ProtocolAddress.BASE_CONFIG.value + 28)
        self.struct.add_uint_field("cfg_protocol_version", ProtocolAddress.BASE_CONFIG.value + 30)

        # HomeData
        self.struct.add_decimal_field("pack_voltage", ProtocolAddress.HOME_DATA.value + 0, 2)
        self.struct.add_decimal_field("pack_current", ProtocolAddress.HOME_DATA.value + 2, 1)
        self.struct.add_uint_field("pack_soc", ProtocolAddress.HOME_DATA.value + 4)
        self.struct.add_uint_field("pack_charging_status", ProtocolAddress.HOME_DATA.value + 6)
        self.struct.add_uint_field("pack_chg_full_time", ProtocolAddress.HOME_DATA.value + 8)
        self.struct.add_uint_field("pack_dsg_empty_time", ProtocolAddress.HOME_DATA.value + 10)
        self.struct.add_uint_field("pack_aging_data_bin", ProtocolAddress.HOME_DATA.value + 12)
        self.struct.add_uint8_field("pack_cnts", ProtocolAddress.HOME_DATA.value + 15)
        self.struct.add_uint_field("pack_online_bin", ProtocolAddress.HOME_DATA.value + 16)
        self.struct.add_uint_field("can_bus_fault_bin", ProtocolAddress.HOME_DATA.value + 18)
        self.struct.add_swap_string_field("device_model", ProtocolAddress.HOME_DATA.value + 20, 6)
        self.struct.add_sn_field("device_sn", ProtocolAddress.HOME_DATA.value + 32)
        self.struct.add_uint8_field("inv_number", ProtocolAddress.HOME_DATA.value + 41)
        self.struct.add_uint_field("inv_online_bin", ProtocolAddress.HOME_DATA.value + 42)
        self.struct.add_uint8_field("inv_power_type", ProtocolAddress.HOME_DATA.value + 45)

        # pv_to_battery      = 1 << 0
        # grid_to_battery    = 1 << 1
        # battery_to_grid    = 1 << 2
        # ac_load            = 1 << 3
        # dc_load            = 1 << 4
        # battery_to_invert  = 1 << 5
        # invert_to_battery  = 1 << 6
        # grid_to_load       = 1 << 7
        # pv_icon            = 1 << 8
        # grid_icon          = 1 << 9
        # ac_load_icon       = 1 << 10
        # pv_to_grid         = 1 << 11
        # pv_to_ac_load      = 1 << 12
        # battery_to_ac_load = 1 << 13
        self.struct.add_uint_field("energy_lines", ProtocolAddress.HOME_DATA.value + 46)

        # See CtrlStatusMask
        self.struct.add_uint_field("ctrl_status", ProtocolAddress.HOME_DATA.value + 48)

        self.struct.add_uint8_field("grid_parallel_soc", ProtocolAddress.HOME_DATA.value + 51)
        self.struct.add_uint32_field("total_dc_power", ProtocolAddress.HOME_DATA.value + 80)
        self.struct.add_uint32_field("total_ac_power", ProtocolAddress.HOME_DATA.value + 84)
        self.struct.add_uint32_field("total_pv_power", ProtocolAddress.HOME_DATA.value + 88)
        self.struct.add_uint32_field("total_grid_power", ProtocolAddress.HOME_DATA.value + 92)
        self.struct.add_uint32_field("total_inv_power", ProtocolAddress.HOME_DATA.value + 96)
        self.struct.add_decimal32_field("total_dc_energy", ProtocolAddress.HOME_DATA.value + 100, 1)
        self.struct.add_decimal32_field("total_ac_energy", ProtocolAddress.HOME_DATA.value + 104, 1)
        self.struct.add_decimal32_field("total_pv_charging_energy", ProtocolAddress.HOME_DATA.value + 108, 1)
        self.struct.add_decimal32_field("total_grid_charging_energy", ProtocolAddress.HOME_DATA.value + 112, 1)
        self.struct.add_decimal32_field("total_feedback_energy", ProtocolAddress.HOME_DATA.value + 116, 1)
        self.struct.add_enum_field("charging_mode", ProtocolAddress.HOME_DATA.value + 120, ChargingMode)

        self.struct.add_uint8_field("inv_working_status", ProtocolAddress.HOME_DATA.value + 123)
        self.struct.add_uint32_field("pv_to_ac_energy", ProtocolAddress.HOME_DATA.value + 124)
        self.struct.add_uint8_field("self_sufficiency_rate", ProtocolAddress.HOME_DATA.value + 129)
        self.struct.add_uint32_field("pv_to_ac_power", ProtocolAddress.HOME_DATA.value + 130)
        self.struct.add_uint32_field("pack_dsg_energy_total", ProtocolAddress.HOME_DATA.value + 134)
        self.struct.add_uint_field("rate_voltage", ProtocolAddress.HOME_DATA.value + 138)
        self.struct.add_uint_field("rate_frequency", ProtocolAddress.HOME_DATA.value + 140)

        # Inverter GridInfo
        self.struct.add_decimal_field("grid_frequency", ProtocolAddress.INV_GRID_INFO.value + 0, 1)
        self.struct.add_uint32_field("total_grid_power", ProtocolAddress.INV_GRID_INFO.value + 2)
        self.struct.add_decimal32_field("grid_total_chg_energy", ProtocolAddress.INV_GRID_INFO.value + 6, 1)
        self.struct.add_decimal32_field("grid_total_feedback_energy", ProtocolAddress.INV_GRID_INFO.value + 10, 1)
        self.struct.add_uint8_field("grid_num_phases", ProtocolAddress.INV_GRID_INFO.value + 25)
        self.struct.add_uint_field("grid_phase0_power", ProtocolAddress.INV_GRID_INFO.value + 26)
        self.struct.add_decimal_field("grid_phase0_voltage", ProtocolAddress.INV_GRID_INFO.value + 28, 1)
        self.struct.add_decimal_field("grid_phase0_current", ProtocolAddress.INV_GRID_INFO.value + 30, 1)

        # Inverter LoadInfo
        self.struct.add_uint32_field("total_dc_power", ProtocolAddress.INV_LOAD_INFO.value + 0)
        self.struct.add_decimal32_field("total_dc_energy", ProtocolAddress.INV_LOAD_INFO.value + 4, 1)
        self.struct.add_uint_field("dc_5v_power", ProtocolAddress.INV_LOAD_INFO.value + 8)
        self.struct.add_decimal_field("dc_5v_current", ProtocolAddress.INV_LOAD_INFO.value + 10, 1)
        self.struct.add_uint_field("dc_12v_power", ProtocolAddress.INV_LOAD_INFO.value + 12)
        self.struct.add_decimal_field("dc_12v_current", ProtocolAddress.INV_LOAD_INFO.value + 14, 1)
        self.struct.add_uint_field("dc_24v_power", ProtocolAddress.INV_LOAD_INFO.value + 16)
        self.struct.add_decimal_field("dc_24v_current", ProtocolAddress.INV_LOAD_INFO.value + 18, 1)
        self.struct.add_uint32_field("dc_load_total_power_2", ProtocolAddress.INV_LOAD_INFO.value + 40)
        self.struct.add_decimal32_field("dc_load_total_energy_2", ProtocolAddress.INV_LOAD_INFO.value + 44, 1)

        self.struct.add_uint8_field("inv_num_phases", ProtocolAddress.INV_LOAD_INFO.value + 59)
        self.struct.add_uint_field("inv_phase0_power", ProtocolAddress.INV_LOAD_INFO.value + 60)
        self.struct.add_decimal_field("inv_phase0_voltage", ProtocolAddress.INV_LOAD_INFO.value + 62, 1)
        self.struct.add_decimal_field("inv_phase0_current", ProtocolAddress.INV_LOAD_INFO.value + 64, 1)

        # Pack info
        self.struct.add_uint_field("pack_volt_type", ProtocolAddress.PACK_MAIN_INFO.value + 0)
        self.struct.add_uint8_field("pack_cnts", ProtocolAddress.PACK_MAIN_INFO.value + 3)
        self.struct.add_decimal_field("pack_voltage", ProtocolAddress.PACK_MAIN_INFO.value + 6, 2)
        self.struct.add_decimal_field("pack_current", ProtocolAddress.PACK_MAIN_INFO.value + 8, 1)
        self.struct.add_uint8_field("pack_soc", ProtocolAddress.PACK_MAIN_INFO.value + 11)
        self.struct.add_uint8_field("pack_soh", ProtocolAddress.PACK_MAIN_INFO.value + 13)
        # Celsius + 40?
        self.struct.add_uint_field("pack_avg_temp", ProtocolAddress.PACK_MAIN_INFO.value + 14, offset=-40)
        self.struct.add_uint8_field("pack_running_status", ProtocolAddress.PACK_MAIN_INFO.value + 17)
        # 1 charging, 2 discharging
        self.struct.add_uint8_field("pack_charging_status", ProtocolAddress.PACK_MAIN_INFO.value + 19)
        self.struct.add_decimal_field("pack_max_chg_voltage", ProtocolAddress.PACK_MAIN_INFO.value + 20, 2)
        self.struct.add_decimal_field("pack_max_chg_current", ProtocolAddress.PACK_MAIN_INFO.value + 22, 1)
        self.struct.add_decimal_field("pack_max_dsg_current", ProtocolAddress.PACK_MAIN_INFO.value + 24, 1)

        mqtt_name_map = {
            'ac_switch': 'ac_output_on',
            'dc_switch': 'dc_output_on',
            'total_pv_power': 'dc_input_power',
            'total_grid_power': 'ac_input_power',
            'total_ac_power': 'ac_output_power',
            'total_dc_power': 'dc_output_power',
            # '': 'power_generation', # PV
            'pack_soc': 'total_battery_percent',
            # '': 'ac_output_on',
            # '': 'dc_output_on',
            # '': 'ac_output_mode',
            'inv_phase0_voltage': 'internal_ac_voltage',
            'inv_phase0_current': 'internal_current_one',
            'inv_phase0_power': 'internal_power_one',
            # '': 'internal_ac_frequency',
            # '': 'internal_current_two',
            # '': 'internal_power_two',
            'grid_phase0_voltage': 'ac_input_voltage',
            # '': 'internal_current_three',
            # '': 'internal_power_three',
            'grid_frequency': 'ac_input_frequency',
            'pack_voltage': 'total_battery_voltage',
            'pack_current': 'total_battery_current',
            # '': 'ups_mode',
            # '': 'split_phase_on',
            # '': 'split_phase_machine_mode',
            # '': 'grid_charge_on',
            # '': 'time_control_on',
            # '': 'battery_range_start',
            # '': 'battery_range_end',
            # '': 'led_mode',
            # '': 'power_off',
            # '': 'auto_sleep_mode',
            # '': 'eco_on',
            # '': 'eco_shutdown',
            # '': 'charging_mode',
            # '': 'power_lifting_on',
            # PV
            # '': 'dc_input_voltage1',
            # '': 'dc_input_power1',
            # '': 'dc_input_current1',
            # '': 'pack_status',
        }

        for field in self.struct.fields:
            if (new_name := mqtt_name_map.get(field.name)) is not None:
                field.name = new_name

    @property
    def polling_commands(self) -> List[ReadHoldingRegisters]:
        return [
            ReadHoldingRegisters(ProtocolAddress.HOME_DATA.value, 67),
            ReadHoldingRegisters(ProtocolAddress.INV_GRID_INFO.value, 31),
            ReadHoldingRegisters(ProtocolAddress.INV_LOAD_INFO.value, 48),
            ReadHoldingRegisters(ProtocolAddress.PACK_MAIN_INFO.value, 31),
        ]

    @property
    def logging_commands(self) -> List[ReadHoldingRegisters]:
        return [
            # A few of these depend on the protocol version, but newer protocols
            # # seem to just add values after the existing ones
            ReadHoldingRegisters(ProtocolAddress.BASE_CONFIG.value, 16),
            ReadHoldingRegisters(ProtocolAddress.HOME_DATA.value, 67),
            ReadHoldingRegisters(ProtocolAddress.INV_GRID_INFO.value, 31),
            ReadHoldingRegisters(ProtocolAddress.INV_LOAD_INFO.value, 48),
            ReadHoldingRegisters(ProtocolAddress.PACK_MAIN_INFO.value, 31),
        ]

    @property
    def writable_ranges(self) -> List[range]:
        switches = range(ProtocolAddress.AC_SWITCH.value, ProtocolAddress.DC_SWITCH.value + 1)
        if len(switches) != 2:
            raise RuntimeError("We only expect two values in this 'range'")
        return [switches]

    def parse(self, address: int, data: bytes) -> dict:
        """Insert extra virtual fields, like bitfields that need to be unpacked
        """
        ret = self.struct.parse(address, data)
        if ctrl_status := ret.get("ctrl_status"):
            ret["ac_output_on"] = ctrl_status & CtrlStatusMask.AC_ENABLE.value
            ret["dc_output_on"] = ctrl_status & CtrlStatusMask.DC_ENABLE.value
        return ret
