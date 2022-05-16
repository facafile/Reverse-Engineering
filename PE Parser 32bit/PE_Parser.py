#contants of the header sizes
SIZE_OF_PE=24
SIZE_OF_SECTION_HEADER=40

#function that converts relative virtual address to the phisical offset
def RVA_to_offset(rva):
    section_info=find_section(rva)
    return rva + section_info[1] - section_info[0]

#function that determines which section does the relative virtual address fall in and returns the pointer to the start of that section
def find_section(rva):
    global mz, pe
    num_of_sections = pe.num_of_sections

    sections_pointer = mz.new_header_offset + SIZE_OF_PE + pe.size_of_opt_header

    for i in range(num_of_sections):
        if little_endian(sections_pointer + 12, 4) <= rva <= \
                little_endian(sections_pointer + 12, 4) + little_endian(sections_pointer + 8, 4):
            return little_endian(sections_pointer + 12, 4), little_endian(sections_pointer + 20, 4)
        sections_pointer += SIZE_OF_SECTION_HEADER

#if anything happens that we don't want this function is called, error message is outputed and the program is stoped
def error_wrong_format():
    print("File not the right format!")
    exit(0)

#this function converts data from a file in to it's little endian representation in a form of a integer, arguments are pointer to the start of the data
#we want to read and it's size in bytes
def little_endian(pointer, size):
    global data
    return int.from_bytes(data[pointer:pointer + size], "little")

#takes an integer that is a representation of a hex value and makes a hex value in string format padded with leading zeros to the wanted numbers of digits
def add_Padding_str(value, digit_num):
    return '0x{0:0{1}X}'.format(value, digit_num)

#this function makes an array of tables that go to the end of the optional header
def return_tables(pointer,size):
    table_list=[]
    pom_pointer=pointer
    for i in range(size):
        table_list.append(data_dir(little_endian(pom_pointer,4),little_endian(pom_pointer+4,4)))
        pom_pointer+=8
    return table_list

#takes an integer representing a hex value in little endian and returns ASCII string of it
def string_from_int_representation_of_hex(value):
    name_to_convert = str(hex(value)).partition("x")[2]
    name = bytes.fromhex(name_to_convert).decode('utf-8')
    return name[::-1]

#takes array of section headers and it returns them as a formated string whit all it's parts
def section_headers_merge(section_headers):
    output="====================\n= Section Headers =\n====================\n"
    for i in range(len(section_headers)):
        output+=section_headers[i].write()
    return output


#array containing full names of fields of the mz header, used names of the fields in the structure and the field size in bytes
mz_param=[
    ("Magic","magic",2),
    ("Bytes on Last Page of File","last_page_bytes",2),
    ("Pages in File","pages_in_file",2),
    ("Relocations","relocations",2),
    ("Size of Header in Paragraphs","size_of_header_in_paragraphs",2),
    ("Minimum Extra Paragraphs","min_extra_par",2),
    ("Maximum Extra Paragraphs","max_extra_par",2),
    ("Initial (relative) SS","initial_SS",2),
    ("Initial SP","initial_SP",2),
    ("Checksum","checksum",2),
    ("Initial IP","initial_IP",2),
    ("Initial (relative) CS","initial_CS",2),
    ("Offset to Relocation Table","offset_relocation",2),
    ("Overlay Number","overlay_num",2),
    ("Reserved",2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("Reserved", 2),
    ("OEM Identifier","OEM_ident", 2),
    ("OEM Information","OEM_info", 2),
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
    ("Offset to New Header","new_header_offset", 4)

]

#array containing full names of fields of the pe header, used names of the fields in the structure and the field size in bytes
pe_param = [
    ("Magic","magic",4),
    ("Machine", "machine",2),
    ("Number of Sections","num_of_sections", 2),
    ("Time Date Stamp", "time_date_stamp",4),
    ("Pointer to Symbol Table","pointer_to_symbol", 4),
    ("Number of Symbols", "num_of_symbols",4),
    ("Size of Optional Header","size_of_opt_header", 2),
    ("Characteristics", "characteristics",2),

]

#array containing full names of fields of the optional header, used names of the fields in the structure and the field size in bytes
optional_param=[
    ("Magic","magic",2),
    ("Major Linker Version","maj_link_version", 1),
    ("Minor Linker Version", "min_link_verion",1),
    ("Size of Code","size_of_code", 4),
    ("Size of Initialized Data","size_init_data", 4),
    ("Size of Uninitialized Data","size_uninit_data", 4),
    ("Adress of Entry Point","addr_entry", 4),
    ("Base of Code","base_code", 4),
    ("Base of Data", "base_data",4),
    ("Image Base", "image_base",4),
    ("Section Alignment","sect_align", 4),
    ("File Alignment", "file_align",4),
    ("Major O/S Version","maj_os_ver", 2),
    ("Minor O/S Version", "min_os_ver",2),
    ("Major Image Version","maj_img_ver", 2),
    ("Minor Image Version", "min_img_ver",2),
    ("Major Subsystem Version","maj_subsys_ver", 2),
    ("Minor Subsystem Version", "min_subsys_ver",2),
    ("Win32 Version Value","win32_ver", 4),
    ("Size of Image","size_img", 4),
    ("Size of Headers","size_headers", 4),
    ("Checksum", "checksum",4),
    ("Subsystem","subsys", 2),
    ("DLL Characteristics","dll_char", 2),
    ("Size of Stack Reserve","size_stack_res", 4),
    ("Size of Stack Commit", "size_stack_comm",4),
    ("Size of Heap Reserve","size_heap_res", 4),
    ("Size of Heap Commit", "size_heap_comm",4),
    ("Loader Flags","loader_flags", 4),
    ("Number of Data Directories","num_data_dirs", 4),

]

#array containing full names of fields of the section header, used names of the fields in the structure and the field size in bytes
section_param=[
    ("Name","name",8),
    ("Virtual Size","virt_size",4),
    ("RVA","rva",4),
    ("Size of Raw Data","size_raw",4),
    ("Pointer to Raw Data","pointer_raw",4),
    ("Pointer to Relocations","pointer_reloc",4),
    ("Pointer to Line Numbers","pointer_line_mem",4),
    ("Number of Relocations","num_reloc",2),
    ("Number of Line Numbers","num_line_num",2),
    ("Characteristics","characteristics",4)

]

#names of the direcories that are cointained on the end of the optional header (size for every directory is 8 bytes, 4 for the name and 4 for the size)
data_dir_names=[
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

#costum structure that consists of relative virtual adres of a data directory and the size of it
#this is used in the initialising of the optional header
class data_dir:
    def __init__(self,rva,size):
        self.rva=rva
        self.size=size

#mz header structure
class MZ_header:
   def __init__(self):
       self.magic=little_endian(0,2)
       self.last_page_bytes=little_endian(2,2)
       self.pages_in_file=little_endian(4,2)
       self.relocations=little_endian(6,2)
       self.size_of_header_in_paragraphs=little_endian(8,2)
       self.min_extra_par=little_endian(10,2)
       self.max_extra_par=little_endian(12,2)
       self.initial_SS=little_endian(14,2)
       self.initial_SP=little_endian(16,2)
       self.checksum=little_endian(18,2)
       self.initial_IP=little_endian(20,2)
       self.initial_CS=little_endian(22,2)
       self.offset_relocation=little_endian(24,2)
       self.overlay_num=little_endian(26,2)
       self.OEM_ident=little_endian(38,2)
       self.OEM_info=little_endian(40,2)
       self.new_header_offset=little_endian(60,4)

   #checking if the magic numbers are correct
   def check(self):
       if self.magic !=int.from_bytes(b'MZ',"little"):
           error_wrong_format()

   #formated output for every part of the mz header returned as a string
   def write(self):
       output="====================\n=    MZ Header    =\n====================\n"

       elements=vars(self)
       header_name="--> MZ"
       reserved='{: <5}{: <30}: {: <10}\n'.format("", "reserved" ,
                                                        add_Padding_str(0, 4))
       for i in range(14):
           if mz_param[i][1]!="magic":
               header_name=""
           output+='{: <5}{: <30} {: <10}{}\n'.format("", mz_param[i][0] + ":",
                                   add_Padding_str(elements[mz_param[i][1]], mz_param[i][2] * 2),
                                   header_name)


       for i in range(4):
           output +=reserved
       for i in range(18,20):
           output += '{: <5}{: <30}: {: <10}\n'.format("", mz_param[i][0] ,
                                                        add_Padding_str(elements[mz_param[i][1]], mz_param[i][2] * 2))

       for i in range(10):
           output += reserved
       output+= '{: <5}{: <30}: {: <10}\n'.format("", mz_param[30][0] ,
                                                        add_Padding_str(elements[mz_param[30][1]], mz_param[30][2] * 2))
       output+="\n"
       return output

#pe header structure
class PE_header:
    def __init__(self,pointer):
        self.magic=little_endian(pointer,4)
        self.machine=little_endian(pointer+4,2)
        self.num_of_sections=little_endian(pointer+6,2)
        self.time_date_stamp=little_endian(pointer+8,4)
        self.pointer_to_symbol=little_endian(pointer+12,4)
        self.num_of_symbols=little_endian(pointer+16,4)
        self.size_of_opt_header=little_endian(pointer+20,2)
        self.characteristics=little_endian(pointer+22,2)

    # checking if the magic numbers are correct
    def check(self):
        if self.magic != int.from_bytes(b'\x50\x45\x00\x00', "little"):
            error_wrong_format()

    # formated output for every part of the pe header returned as a string
    def write(self):
        output="====================\n=    PE Header    =\n====================\n"
        elements=vars(self)
        header_name="--> PE"

        for i in range(len(elements)):
            if pe_param[i][1]!="magic":
                header_name=""
            output+='{: <5}{: <30}: {: <10} {}\n'.format("", pe_param[i][0] ,
                                                        add_Padding_str(elements[pe_param[i][1]], pe_param[i][2] * 2),header_name)

        output+="\n"

        return output

#optional header structure
class Optional_header:
    def __init__(self,pointer):
        self.magic=little_endian(pointer,2)
        self.maj_link_version=little_endian(pointer+2,1)
        self.min_link_verion=little_endian(pointer+3,1)
        self.size_of_code=little_endian(pointer+4,4)
        self.size_init_data=little_endian(pointer+8,4)
        self.size_uninit_data=little_endian(pointer+12,4)
        self.addr_entry=little_endian(pointer+16,4)
        self.base_code=little_endian(pointer+20,4)
        self.base_data=little_endian(pointer+24,4)
        self.image_base=little_endian(pointer+28,4)
        self.sect_align=little_endian(pointer+32,4)
        self.file_align=little_endian(pointer+36,4)
        self.maj_os_ver=little_endian(pointer+40,2)
        self.min_os_ver=little_endian(pointer+42,2)
        self.maj_img_ver=little_endian(pointer+44,2)
        self.min_img_ver=little_endian(pointer+46,2)
        self.maj_subsys_ver=little_endian(pointer+48,2)
        self.min_subsys_ver=little_endian(pointer+50,2)
        self.win32_ver=little_endian(pointer+52,4)
        self.size_img=little_endian(pointer+56,4)
        self.size_headers=little_endian(pointer+60,4)
        self.checksum=little_endian(pointer+64,4)
        self.subsys=little_endian(pointer+68,2)
        self.dll_char=little_endian(pointer+70,2)
        self.size_stack_res=little_endian(pointer+72,4)
        self.size_stack_comm=little_endian(pointer+76,4)
        self.size_heap_res=little_endian(pointer+80,4)
        self.size_heap_comm=little_endian(pointer+84,4)
        self.loader_flags=little_endian(pointer+88,4)
        self.num_data_dirs=little_endian(pointer+92,4)
        self.tables =return_tables(pointer+96,16)

    #checking if the magic numbers are correct
    def check(self):
        if self.magic != int.from_bytes(b'\x0B\x01', "little"):
            error_wrong_format()

    #formated output for every part of the optional header returned as a string
    def write(self):
        output="====================\n= Optional Header =\n====================\n"
        phis_adress=""
        elements=vars(self)

        for i in range(len(elements)-1):
            if optional_param[i][1]=="addr_entry":
                phis_adress="(physical: "+add_Padding_str(RVA_to_offset(elements[optional_param[i][1]]),10)+")"

            output += '{: <5}{: <30}: {: <10} {: <25}\n'.format("", optional_param[i][0],
                                                       add_Padding_str(elements[optional_param[i][1]], optional_param[i][2] * 2),phis_adress)

            phis_adress=""

        output += 50 * "-" + "\n"

        for i in range(len(self.tables)):

            output+='{: <5}{: <10} {: <4} {: <25}\n'.format("",add_Padding_str(self.tables[i].rva,8),"RVA",data_dir_names[i])
            output += '{: <5}{: <10} {: <4}\n'.format("", add_Padding_str(self.tables[i].size, 8), "size")
            output += 50 * "-" + "\n"

        output+="\n"

        return output

#section header strucuture
class Section_header:
    def __init__(self,pointer):
        self.name=little_endian(pointer,8)
        self.virt_size=little_endian(pointer+8,4)
        self.rva=little_endian(pointer+12,4)
        self.size_raw=little_endian(pointer+16,4)
        self.pointer_raw=little_endian(pointer+20,4)
        self.pointer_reloc=little_endian(pointer+24,4)
        self.pointer_line_mem=little_endian(pointer+28,4)
        self.num_reloc=little_endian(pointer+32,2)
        self.num_line_num=little_endian(pointer+34,2)
        self.characteristics=little_endian(pointer+36,4)

    # formated output for every part of the section header returned as a string
    def write(self):
        output=""
        elements=vars(self)
        name_str=string_from_int_representation_of_hex(self.name)
        output+='{: <5}{: <25}: {:<8}\n'.format("",section_param[0][0],name_str)

        for i in range(1,len(elements)):
            output+='{: <5}{: <25}: {:<10}\n'.format("",section_param[i][0],add_Padding_str(elements[section_param[i][1]],section_param[i][2]*2))
        output+="\n"
        return output

    #def check(self):



if __name__ == '__main__':
    #variable from where we will print the output
    output = ""
    #pointer = 0 mislin da mi ovo tu ne triba al provjericu jos

    # open a file and read the bytes from it
    file_name = input("Write PE path:")
    file = open(file_name, "rb")
    data = file.read()

    #load the mz header, check if it is correct and write it to the output
    mz=MZ_header()
    mz.check()
    output+=mz.write()

    #load the pe header, check if it is correct and write it to the output
    pe=PE_header(mz.new_header_offset)
    pe.check()
    output+=pe.write()

    # load the optional header, check if it is correct and write it to the output
    opt=Optional_header(mz.new_header_offset+SIZE_OF_PE)
    output+=opt.write()

    ##load the section headers and write them to the output
    sect=[]
    for i in range(pe.num_of_sections):
        sect.append(Section_header(mz.new_header_offset+SIZE_OF_PE+pe.size_of_opt_header+i*SIZE_OF_SECTION_HEADER))
    output+=section_headers_merge(sect)

    print(output)