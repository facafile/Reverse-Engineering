# header sizes
SIZE_OF_PE = 24
SIZE_OF_SECTION_HEADER = 40
SIZE_OF_IMPORT_DIRECTORY = 20

INDENT = 5

BYTES_8 = 8
BYTES_4 = 4
BYTES_2 = 2
BYTES_1 = 1

#returns a underlined string with the desiered times of indentation
def format_string(string, indent_times):
    return '{}{}\n{}{}\n'.format(INDENT * indent_times * " ", string, INDENT * indent_times * " ", len(string) * "=")

#gets the dll name from the data starting at the given pointer
def get_dll_name(rva, data, num_of_sections, pe_header_offset, opt_header_size):
    string = ""
    i = 0
    phis_off = RVA_to_offset(data, rva, num_of_sections, pe_header_offset, opt_header_size)

    while data[phis_off + i] != 0:
        string += chr(data[phis_off + i])
        i += 1

    return string

# function that converts relative virtual address to the physical offset
def RVA_to_offset(data, rva, num_of_sections, pe_header_offset, opt_header_size):
    section_info = find_section(data, rva, num_of_sections, pe_header_offset, opt_header_size)

    return rva + section_info[1] - section_info[0]

# function that determines which section does the relative virtual address fall in and returns the pointer to the start of that section
def find_section(data, rva, num_of_sections, pe_header_offset, opt_header_size):
    sections_pointer = pe_header_offset + SIZE_OF_PE + opt_header_size

    for i in range(num_of_sections):
        is_in_section = little_endian(data, sections_pointer + 12, 4) <= rva <= \
                        little_endian(data, sections_pointer + 12, 4) + little_endian(data, sections_pointer + 8, 4)

        if is_in_section:
            return little_endian(data, sections_pointer + 12, 4), little_endian(data, sections_pointer + 20, 4)

        sections_pointer += SIZE_OF_SECTION_HEADER

# if anything happens that we don't want this function is called, error message is outputed and the program is stoped
def error_wrong_format():
    print("File not the right format!")
    exit(0)

# this function converts data from a file in to it's little endian representation in a form of a integer
def little_endian(data, pointer, size):
    return int.from_bytes(data[pointer:pointer + size], "little")

# takes an integer that is a representation of a hex value and makes a hex value in string format padded with leading zeros to the wanted numbers of bytes
def add_padding_str(value, bytes):
    return '0x{0:0{1}X}'.format(value, bytes*2)

# this function makes an array of tables that go to the end of the optional header
def return_tables(data, pointer, size):
    table_list = []
    pom_pointer = pointer
    for i in range(size):
        table_list.append(data_dir(little_endian(data, pom_pointer, 4), little_endian(data, pom_pointer + 4, 4)))
        pom_pointer += BYTES_8

    return table_list

# takes an integer representing a hex value in little endian and returns ASCII string of it
def string_from_int_representation_of_hex(value):
    name_to_convert = str(hex(value)).partition("x")[2]
    name = bytes.fromhex(name_to_convert).decode('utf-8')

    return name[::-1]

# takes array of section headers and it returns them as a formatted string with all it's parts
def section_headers_merge(section_headers):
    output = format_string("Section Headers", 0)

    for i in range(len(section_headers)):
        output += section_headers[i].write()

    return output

#merges output for import direcotries
def imports_merge(import_direct, data, num_of_sections, pe_header_offset, opt_header_size):
    output = format_string("Import Table", 0)

    for i in range(len(import_direct)):
        output += import_direct[i].write(data, num_of_sections, pe_header_offset, opt_header_size)

    output += "\n"

    return output

# array containing full names of fields of the mz header, used names of the fields in the structure and the field size in bytes
mz_param = [
    ("Magic", "magic", 2),
    ("Bytes on Last Page of File", "last_page_bytes", 2),
    ("Pages in File", "pages_in_file", 2),
    ("Relocations", "relocations", 2),
    ("Size of Header in Paragraphs", "size_of_header_in_paragraphs", 2),
    ("Minimum Extra Paragraphs", "min_extra_par", 2),
    ("Maximum Extra Paragraphs", "max_extra_par", 2),
    ("Initial (relative) SS", "initial_SS", 2),
    ("Initial SP", "initial_SP", 2),
    ("Checksum", "checksum", 2),
    ("Initial IP", "initial_IP", 2),
    ("Initial (relative) CS", "initial_CS", 2),
    ("Offset to Relocation Table", "offset_relocation", 2),
    ("Overlay Number", "overlay_num", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("OEM Identifier", "OEM_ident", 2),
    ("OEM Information", "OEM_info", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Offset to New Header", "new_header_offset", 4)

]

# array containing full names of fields of the pe header, used names of the fields in the structure and the field size in bytes
pe_param = [
    ("Magic", "magic", 4),
    ("Machine", "machine", 2),
    ("Number of Sections", "num_of_sections", 2),
    ("Time Date Stamp", "time_date_stamp", 4),
    ("Pointer to Symbol Table", "pointer_to_symbol", 4),
    ("Number of Symbols", "num_of_symbols", 4),
    ("Size of Optional Header", "size_of_opt_header", 2),
    ("Characteristics", "characteristics", 2),

]

# array containing full names of fields of the optional header, used names of the fields in the structure and the field size in bytes
optional_param = [
    ("Magic", "magic", 2),
    ("Major Linker Version", "maj_link_version", 1),
    ("Minor Linker Version", "min_link_verion", 1),
    ("Size of Code", "size_of_code", 4),
    ("Size of Initialized Data", "size_init_data", 4),
    ("Size of Uninitialized Data", "size_uninit_data", 4),
    ("Address of Entry Point", "addr_entry", 4),
    ("Base of Code", "base_code", 4),
    ("Base of Data", "base_data", 4),
    ("Image Base", "image_base", 4),
    ("Section Alignment", "sect_align", 4),
    ("File Alignment", "file_align", 4),
    ("Major O/S Version", "maj_os_ver", 2),
    ("Minor O/S Version", "min_os_ver", 2),
    ("Major Image Version", "maj_img_ver", 2),
    ("Minor Image Version", "min_img_ver", 2),
    ("Major Subsystem Version", "maj_subsys_ver", 2),
    ("Minor Subsystem Version", "min_subsys_ver", 2),
    ("Win32 Version Value", "win32_ver", 4),
    ("Size of Image", "size_img", 4),
    ("Size of Headers", "size_headers", 4),
    ("Checksum", "checksum", 4),
    ("Subsystem", "subsys", 2),
    ("DLL Characteristics", "dll_char", 2),
    ("Size of Stack Reserve", "size_stack_res", 4),
    ("Size of Stack Commit", "size_stack_comm", 4),
    ("Size of Heap Reserve", "size_heap_res", 4),
    ("Size of Heap Commit", "size_heap_comm", 4),
    ("Loader Flags", "loader_flags", 4),
    ("Number of Data Directories", "num_data_dirs", 4),

]

# array containing full names of fields of the section header, used names of the fields in the structure and the field size in bytes
section_param = [
    ("Name", "name", 8),
    ("Virtual Size", "virt_size", 4),
    ("RVA", "rva", 4),
    ("Size of Raw Data", "size_raw", 4),
    ("Pointer to Raw Data", "pointer_raw", 4),
    ("Pointer to Relocations", "pointer_reloc", 4),
    ("Pointer to Line Numbers", "pointer_line_mem", 4),
    ("Number of Relocations", "num_reloc", 2),
    ("Number of Line Numbers", "num_line_num", 2),
    ("Characteristics", "characteristics", 4)

]

# names of the direcories that are cointained on the end of the optional header (size for every directory is 8 bytes, 4 for the name and 4 for the size)
data_dir_names = [
    "EXPORT Table",
    "IMPORT Table",
    "RESOURCE Table",
    "EXCEPTION Table",
    "CERTIFICATE Table",
    "BASE RELOCATION Table",
    "DEBUG Directory",
    "ARCHITECTURE SPECIFIC Data",
    "GLOBAL POINTER Register",
    "TLS Table",
    "LOAD CONFIG Table",
    "BOUND Import",
    "IMPORT ADRESS Table",
    "DELAY IMPORT Descriptor",
    "CLI Header",
    "RESERVED"
]

#names of the atributes that are cointained in the import directory, variable names for that attributes and their size
import_table_names = [("Import Lookup Table RVA", "import_lookup_rva", 4),
                      ("Time/Date Stamp", "stamp", 4),
                      ("Forwarder Chain", "chain", 4),
                      ("Name RVA", "name_rva", 4),
                      ("Import Address Table RVA", "import_addr_rva", 4),
                      ]

#names of the atributes that are cointained in the export directory, variable names for that attributes and their size
export_table_names=[("Characteristics","characteristics",4),
                    ("Time Date Stamp","time_date_stamp",4),
                    ("Major Version","maj_version",2),
                    ("Minor Version","min_version",2),
                    ("Name RVA","name_rva",4),
                    ("Ordinal Base","ordinal_base",4),
                    ("Number of Functions","num_of_functions",4),
                    ("Number of Names","num_of_names",4),
                    ("Address Table RVA","addr_table_rva",4),
                    ("Name Pointer Table RVA","name_pointer_rva",4),
                    ("Ordinal Table RVA","ordinal_table_rva",4)]

# costum structure that consists of relative virtual address of a data directory and the size of it
# this is used in the initialising of the optional header
class data_dir:
    def __init__(self, rva, size):
        self.rva = rva
        self.size = size


# mz header structure
class MZ_header:
    def __init__(self, data, pointer):
        self.magic = little_endian(data, pointer, BYTES_2)
        self.last_page_bytes = little_endian(data, pointer + 2, BYTES_2)
        self.pages_in_file = little_endian(data, pointer + 4, BYTES_2)
        self.relocations = little_endian(data, pointer + 6, BYTES_2)
        self.size_of_header_in_paragraphs = little_endian(data, pointer + 8, BYTES_2)
        self.min_extra_par = little_endian(data, pointer + 10, BYTES_2)
        self.max_extra_par = little_endian(data, pointer + 12, BYTES_2)
        self.initial_SS = little_endian(data, pointer + 14, BYTES_2)
        self.initial_SP = little_endian(data, pointer + 16, BYTES_2)
        self.checksum = little_endian(data, pointer + 18, BYTES_2)
        self.initial_IP = little_endian(data, pointer + 20, BYTES_2)
        self.initial_CS = little_endian(data, pointer + 22, BYTES_2)
        self.offset_relocation = little_endian(data, pointer + 24, BYTES_2)
        self.overlay_num = little_endian(data, pointer + 26, BYTES_2)
        self.OEM_ident = little_endian(data, pointer + 38, BYTES_2)
        self.OEM_info = little_endian(data, pointer + 40, BYTES_2)
        self.new_header_offset = little_endian(data, pointer + 60, BYTES_4)

    # checking if the magic numbers are correct
    def check(self):
        if self.magic != int.from_bytes(b'MZ', "little"):
            error_wrong_format()

    # formatted output for every part of the mz header returned as a string
    def write(self):
        output = format_string("MZ HEADER", 0)
        elements = vars(self)
        header_name = "--> MZ"
        reserved = '{: <5}{: <30}: {: <10}\n'.format("", "reserved",
                                                     add_padding_str(0, BYTES_2))
        for i in range(14):
            name_of_atribute = mz_param[i][0]
            name_of_variable = mz_param[i][1]
            size = mz_param[i][2]

            if name_of_variable != "magic":
                header_name = ""

            output += '{: <5}{: <30}: {: <10}{}\n'.format("", name_of_atribute,
                                                          add_padding_str(elements[name_of_variable], size),
                                                          header_name)

        for i in range(4):
            output += reserved

        for i in range(18, 20):
            name_of_atribute = mz_param[i][0]
            name_of_variable = mz_param[i][1]
            size = mz_param[i][2]

            output += '{: <5}{: <30}: {: <10}\n'.format("", name_of_atribute,
                                                        add_padding_str(elements[name_of_variable],size))

        for i in range(10):
            output += reserved

        name_of_atribute = mz_param[30][0]
        name_of_variable = mz_param[30][1]
        size = mz_param[30][2]
        output += '{: <5}{: <30}: {: <10}\n'.format("", name_of_atribute,
                                                    add_padding_str(elements[name_of_variable], size))
        output += "\n"

        return output


# pe header structure
class PE_header:
    def __init__(self,data, pointer):
        self.magic = little_endian(data, pointer, BYTES_4)
        self.machine = little_endian(data, pointer + 4, BYTES_2)
        self.num_of_sections = little_endian(data, pointer + 6, BYTES_2)
        self.time_date_stamp = little_endian(data, pointer + 8, BYTES_4)
        self.pointer_to_symbol = little_endian(data, pointer + 12, BYTES_4)
        self.num_of_symbols = little_endian(data, pointer + 16, BYTES_4)
        self.size_of_opt_header = little_endian(data, pointer + 20, BYTES_2)
        self.characteristics = little_endian(data, pointer + 22, BYTES_2)

    # checking if the magic numbers are correct
    def check(self):
        if self.magic != int.from_bytes(b'\x50\x45\x00\x00', "little"):
            error_wrong_format()

    # formated output for every part of the pe header returned as a string
    def write(self):
        output = format_string("PE header", 0)
        elements = vars(self)
        header_name = "--> PE"

        for i in range(len(elements)):
            name_of_atribute = pe_param[i][0]
            name_of_variable = pe_param[i][1]
            size = pe_param[i][2]

            if name_of_variable != "magic":
                header_name = ""

            output += '{: <5}{: <30}: {: <10} {}\n'.format("", name_of_atribute,
                                                           add_padding_str(elements[name_of_variable],size),
                                                           header_name)

        output += "\n"

        return output


# optional header structure
class Optional_header:
    def __init__(self, data, pointer):
        self.magic = little_endian(data, pointer, BYTES_2)
        self.maj_link_version = little_endian(data, pointer + 2, BYTES_1)
        self.min_link_verion = little_endian(data, pointer + 3, BYTES_1)
        self.size_of_code = little_endian(data, pointer + 4, BYTES_4)
        self.size_init_data = little_endian(data, pointer + 8, BYTES_4)
        self.size_uninit_data = little_endian(data, pointer + 12, BYTES_4)
        self.addr_entry = little_endian(data, pointer + 16, BYTES_4)
        self.base_code = little_endian(data, pointer + 20, BYTES_4)
        self.base_data = little_endian(data, pointer + 24, BYTES_4)
        self.image_base = little_endian(data, pointer + 28, BYTES_4)
        self.sect_align = little_endian(data, pointer + 32, BYTES_4)
        self.file_align = little_endian(data, pointer + 36, BYTES_4)
        self.maj_os_ver = little_endian(data, pointer + 40, BYTES_2)
        self.min_os_ver = little_endian(data, pointer + 42, BYTES_2)
        self.maj_img_ver = little_endian(data, pointer + 44, BYTES_2)
        self.min_img_ver = little_endian(data, pointer + 46, BYTES_2)
        self.maj_subsys_ver = little_endian(data, pointer + 48, BYTES_2)
        self.min_subsys_ver = little_endian(data, pointer + 50, BYTES_2)
        self.win32_ver = little_endian(data, pointer + 52, BYTES_4)
        self.size_img = little_endian(data, pointer + 56, BYTES_4)
        self.size_headers = little_endian(data, pointer + 60, BYTES_4)
        self.checksum = little_endian(data, pointer + 64, BYTES_4)
        self.subsys = little_endian(data, pointer + 68, BYTES_2)
        self.dll_char = little_endian(data, pointer + 70, BYTES_2)
        self.size_stack_res = little_endian(data, pointer + 72, BYTES_4)
        self.size_stack_comm = little_endian(data, pointer + 76, BYTES_4)
        self.size_heap_res = little_endian(data, pointer + 80, BYTES_4)
        self.size_heap_comm = little_endian(data, pointer + 84, BYTES_4)
        self.loader_flags = little_endian(data, pointer + 88, BYTES_4)
        self.num_data_dirs = little_endian(data, pointer + 92, BYTES_4)
        self.tables = return_tables(data, pointer + 96, self.num_data_dirs)

    # checking if the magic numbers are correct
    def check(self):
        if self.magic != int.from_bytes(b'\x0B\x01', "little"):
            error_wrong_format()

    # formatted output for every part of the optional header returned as a string
    def write(self, data, num_of_sections, pe_header_offset, opt_header_size):
        output = format_string("Optional header", 0)
        phys_address = ""
        elements = vars(self)

        for i in range(len(elements) - 1):
            name_of_atribute = optional_param[i][0]
            name_of_variable = optional_param[i][1]
            size = optional_param[i][2]

            if name_of_variable == "addr_entry":
                phys_address = "(physical: " + add_padding_str(RVA_to_offset(data,
                                                                             elements[name_of_variable],
                                                                             num_of_sections,
                                                                             pe_header_offset,
                                                                             opt_header_size), size) + ")"

            output += '{: <5}{: <30}: {: <10} {: <25}\n'.format("", name_of_atribute, add_padding_str(elements[name_of_variable],size), phys_address)

            phys_address = ""

        output += 50 * "-" + "\n"

        for i in range(len(self.tables)):
            output += '{: <5}{: <10} {: <4} {: <25}\n'.format("", add_padding_str(self.tables[i].rva, BYTES_4), "RVA",
                                                              data_dir_names[i])
            output += '{: <5}{: <10} {: <4}\n'.format("", add_padding_str(self.tables[i].size, BYTES_4), "Size")
            output += 50 * "-" + "\n"

        output += "\n"

        return output


# section header structure
class Section_header:
    def __init__(self, data, pointer):
        self.name = little_endian(data, pointer, BYTES_8)
        self.virt_size = little_endian(data, pointer + 8, BYTES_4)
        self.rva = little_endian(data, pointer + 12, BYTES_4)
        self.size_raw = little_endian(data, pointer + 16, BYTES_4)
        self.pointer_raw = little_endian(data, pointer + 20, BYTES_4)
        self.pointer_reloc = little_endian(data, pointer + 24, BYTES_4)
        self.pointer_line_mem = little_endian(data, pointer + 28, BYTES_4)
        self.num_reloc = little_endian(data, pointer + 32, BYTES_2)
        self.num_line_num = little_endian(data, pointer + 34, BYTES_2)
        self.characteristics = little_endian(data, pointer + 36, BYTES_4)

    # formated output for every part of the section header returned as a string
    def write(self):
        output = ""
        elements = vars(self)
        name_str = string_from_int_representation_of_hex(self.name)
        name_of_atribute = section_param[0][0]
        output += '{: <5}{: <25}: {:<8}\n'.format("", name_of_atribute, name_str)

        for i in range(1, len(elements)):
            name_of_atribute = section_param[i][0]
            name_of_variable = section_param[i][1]
            size = section_param[i][2]
            output += '{: <5}{: <25}: {:<10}\n'.format("", name_of_atribute,
                                                       add_padding_str(elements[name_of_variable],
                                                                       size))

        output += "\n"

        return output


class import_directory:
    def __init__(self, data,pointer):
        self.import_lookup_rva = little_endian(data, pointer, BYTES_4)
        self.stamp = little_endian(data, pointer + 4, BYTES_4)
        self.chain = little_endian(data, pointer + 8, BYTES_4)
        self.name_rva = little_endian(data, pointer + 12, BYTES_4)
        self.import_addr_rva = little_endian(data, pointer + 16, BYTES_4)

    def write(self, data, num_of_sections, pe_header_offset, opt_header_size):
        output = format_string("Import Directory", 1)
        elements = vars(self)

        for i in range(len(elements)):
            phis_addr = ""
            name_of_atribute = import_table_names[i][0]
            name_of_variable = import_table_names[i][1]
            size = import_table_names[i][2]
            should_display_phis_addr = name_of_atribute in ("Import Lookup Table RVA", "Name RVA", "Import Address Table RVA") and \
                                     elements[name_of_variable] != 0

            if should_display_phis_addr:
                phis_addr = "(phisycal: " + add_padding_str(RVA_to_offset(data, elements[name_of_variable],
                                                                          num_of_sections, pe_header_offset, opt_header_size),size) + ")"

                if name_of_atribute == "Name RVA":
                    phis_addr += " --> " + get_dll_name(self.name_rva, data, num_of_sections, pe_header_offset, opt_header_size)

            output += '{}{: <25}: {: <10} {}\n'.format(INDENT * 2 * " ", name_of_atribute,add_padding_str(elements[name_of_variable], size), phis_addr)


        if self.import_lookup_rva == 0:
            return output

        output += format_string("Import Thunks", 2)

        phis_thunk = RVA_to_offset(data, self.import_lookup_rva, num_of_sections, pe_header_offset, opt_header_size)
        value = little_endian(data, phis_thunk, BYTES_4)
        counter = 0

        while value != 0:
            if value & (1 << 31):
                ordinal = value & 0xffff
                output += '{}Api: {:<10} {:<7}: {:<4}\n'.format(3 * INDENT * " ", add_padding_str(value, BYTES_4), "Ordinal",
                                                                add_padding_str(ordinal, BYTES_2))

            else:
                hint = little_endian(data, RVA_to_offset(data, value, num_of_sections, pe_header_offset, opt_header_size), BYTES_2)
                name = get_dll_name(value + 2, data, num_of_sections, pe_header_offset, opt_header_size)

                output += '{}Api: {:<10} (physical: {:<10}) --> hint: {:<6}, name: {:<20}\n'.format(3 * INDENT * " ",
                                                                                                    add_padding_str(value, BYTES_4),
                                                                                                    add_padding_str(RVA_to_offset(data,
                                                                                                                                  value,
                                                                                                                                  num_of_sections,
                                                                                                                                  pe_header_offset,
                                                                                                                                  opt_header_size),
                                                                                                                    BYTES_4),
                                                                                                    add_padding_str(hint, BYTES_2), name)

            counter += 1
            value = little_endian(data, phis_thunk + 4 * counter, BYTES_4)

        output += "\n"

        return output


class Export_directory:
    def __init__(self, data, pointer):
        self.characteristics = little_endian(data, pointer, BYTES_4)
        self.time_date_stamp = little_endian(data, pointer + 4, BYTES_4)
        self.maj_version = little_endian(data, pointer + 8, BYTES_2)
        self.min_version = little_endian(data, pointer + 10, BYTES_2)
        self.name_rva = little_endian(data, pointer + 12, BYTES_4)
        self.ordinal_base = little_endian(data, pointer + 16, BYTES_4)
        self.num_of_functions = little_endian(data, pointer + 20, BYTES_4)
        self.num_of_names = little_endian(data, pointer + 24, BYTES_4)
        self.addr_table_rva = little_endian(data, pointer + 28, BYTES_4)
        self.name_pointer_rva = little_endian(data, pointer + 32, BYTES_4)
        self.ordinal_table_rva = little_endian(data, pointer + 36, BYTES_4)

    def write(self, data,num_of_sections, pe_header_offset, opt_header_size, export_dir):
        output = format_string("Export Table", 0) + format_string("Export Directory", 1)
        elements = vars(self)
        phis_addr = ""


        for i in range(len(elements)):
            name_of_attribute = export_table_names[i][0]
            name_of_variable = export_table_names[i][1]
            size = export_table_names[i][2]

            if name_of_attribute in ("Name RVA",
                                            "Address Table RVA",
                                            "Name Pointer Table RVA",
                                            "Ordinal Table RVA"):
                phis_addr = "(physical: " + add_padding_str(RVA_to_offset(data, elements[name_of_variable],
                                                                          num_of_sections, pe_header_offset, opt_header_size), size) + ")"
            if export_table_names[i][0] == "Name RVA":
                phis_addr += "--> " + get_dll_name(self.name_rva, data, num_of_sections, pe_header_offset, opt_header_size)

            output += '{}{:<30} {:<10} {}\n'.format(INDENT * " ", name_of_attribute,
                                                    add_padding_str(elements[name_of_variable],size),phis_addr)
            phis_addr = ""

        ordinals = []
        names = []
        output_second = format_string("Export Function Name Table", 2)
        output_third = format_string("Export Ordinal Table", 2)

        for i in range(self.num_of_names):
            pointer = little_endian(data, RVA_to_offset(data, self.name_pointer_rva + BYTES_4 * i,
                                                                          num_of_sections, pe_header_offset, opt_header_size), BYTES_4)
            name_str = get_dll_name(pointer, data, num_of_sections, pe_header_offset, opt_header_size)
            ordinal=little_endian(data, RVA_to_offset(data, self.ordinal_table_rva + BYTES_2 * i,
                                                                          num_of_sections, pe_header_offset, opt_header_size),BYTES_2) + self.ordinal_base
            output_second += '{}API: {: <10} (phisycal: {}) --> Ordinal: {: <6}, Name: {}\n'.format(INDENT * 3 * " ",
                                                                                                    add_padding_str(pointer,BYTES_4),
                                                                                                    add_padding_str(RVA_to_offset(
                                                                                                                    data,
                                                                                                                    pointer,
                                                                                                                    num_of_sections,
                                                                                                                    pe_header_offset,
                                                                                                                    opt_header_size),BYTES_4),
                                                                                                    add_padding_str(ordinal,BYTES_2),name_str)
            output_third += '{}Value: {: <6} (decoded ordinal: {: <6}), Name: {}\n'.format(INDENT * 3 * " ",
                                                                                           add_padding_str(ordinal - self.ordinal_base,BYTES_2),
                                                                                           add_padding_str(ordinal,BYTES_2),name_str)
            ordinals.append(ordinal)
            names.append((name_str, pointer))

        output += "\n" + format_string("Export Address Table", 2)

        for i in range(self.num_of_functions):
            ordinal_ordered = self.ordinal_base + i
            address = little_endian(data, RVA_to_offset(data, self.addr_table_rva + BYTES_4 * i,
                                                                          num_of_sections, pe_header_offset, opt_header_size), BYTES_4)
            physical = RVA_to_offset(data,address,num_of_sections,pe_header_offset,opt_header_size)

            if address == 0:
                output += '{}{: <10} (physical: {: <10})\n'.format(INDENT * 3 * " ",add_padding_str(address, BYTES_4), add_padding_str(physical, BYTES_4))

            else:
                is_in_export_dir = export_dir.rva <= address <= export_dir.rva + export_dir.size

                if is_in_export_dir:
                    dll_name = get_dll_name(address, data, num_of_sections, pe_header_offset, opt_header_size)

                else:
                    if ordinal_ordered not in ordinals:
                        dll_name = ""

                    else:
                        dll_name = names[ordinals.index(ordinal_ordered)][0]

                output += '{}API: {: <10} (physical: {: <10}) --> Ordinal: {: <6}, Name: {}\n'.format(INDENT * 3 * " ", add_padding_str(address, BYTES_4),
                                                                                                    add_padding_str(physical, BYTES_4),
                                                                                                    add_padding_str(ordinal_ordered, BYTES_2),
                                                                                                    dll_name)

        output += output_second + "\n" + output_third

        return output


if __name__ == '__main__':
    # variable from where we will print the output
    output = ""

    # open a file and read the bytes from it
    file_name = input("Write PE path:")
    file = open(file_name, "rb")
    data = file.read()

    # load the mz header, check if it is correct and write it to output
    mz = MZ_header(data, 0)
    mz.check()
    output += mz.write()

    # load the pe header, check if it is correct and write it to output
    pe = PE_header(data, mz.new_header_offset)
    pe.check()
    output += pe.write()

    # load the optional header, check if it is correct and write it to output
    opt = Optional_header(data, mz.new_header_offset + SIZE_OF_PE)
    opt.check()
    output += opt.write(data, pe.num_of_sections, mz.new_header_offset, pe.size_of_opt_header)

    #load the section headers and write them to output
    sect = []

    for i in range(pe.num_of_sections):
        sect.append(
            Section_header(data, mz.new_header_offset + SIZE_OF_PE + pe.size_of_opt_header + i * SIZE_OF_SECTION_HEADER))

    output += section_headers_merge(sect)

    # load the imports and write them to output
    import_dirs = []
    imports = opt.tables[1]

    for i in range(int(imports.size / SIZE_OF_IMPORT_DIRECTORY)):
        import_dirs.append(import_directory(data, RVA_to_offset(data, imports.rva + i * SIZE_OF_IMPORT_DIRECTORY,
                                                                pe.num_of_sections, mz.new_header_offset, pe.size_of_opt_header)))

    output += imports_merge(import_dirs, data,pe.num_of_sections, mz.new_header_offset, pe.size_of_opt_header)

    #load the exports and write them to output
    exports = opt.tables[0]

    if exports.size != 0:
        export_dir = Export_directory(data, RVA_to_offset(data, exports.rva, pe.num_of_sections, mz.new_header_offset, pe.size_of_opt_header))
        output += export_dir.write(data, pe.num_of_sections, mz.new_header_offset, pe.size_of_opt_header, exports)

    print(output)
    #write=open("out.txt","w")
    #write.write(output)
    #write.close()
    file.close()
