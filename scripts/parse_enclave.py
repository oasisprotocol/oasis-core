#!/usr/bin/env python
"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Copyright (c) 2016 Nagravision S.A.
"""
import argparse

from binascii import hexlify
from struct import unpack
import sys

if sys.version_info[0] != 2:
    print('sorry, parse_enclave.py does not support Python 3 yet :(')
    sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
except:
    print('elftools needed! try: pip install pyelftools')
    sys.exit(1)


def rsa_check(n, s, q1, q2):
    qq1 = s**2 // n
    if qq1 != q1:
        return False
    qq2 = (s**3 - q1*s*n) // n
    if qq2 != q2:
        return False
    return True


class Parser(object):
    def __init__(self, filename):
        # we need to pass a stream to ELFFile
        self.filename = filename
        try:
            self.blob = open(filename, 'rb').read()
        except IOError as e:
            print('%s' % str(e))
            sys.exit(1)

    def find_sgxmeta_header(self):
        sgxmeta_header = "\x4c\x0e\x5d\x63\x94\x02\xa8\x86\x01\x00\x00\x00\x01\x00\x00\x00"
        pos = self.blob.find(sgxmeta_header)
        if pos != -1:
            return pos
        return None

    def find_sigstruct_header(self):
        sigstruct_header = b"\x06\x00\x00\x00\xe1\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
        sigstruct_header2 = b"\x01\x01\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x01\x00\x00\x00"
        # find the first header
        pos = self.blob.find(sigstruct_header)
        if pos != -1:
            # check the second header, 8 bytes after the first one
            if self.blob[pos+24:][:16] == sigstruct_header2:
                # we did a match, return pos
                return pos
        return None

    def find_weak_sigstruct_header(self):
        sigstruct_header = b"\x06\x00\x00\x00\xe1\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x80"
        sigstruct_header2 = b"\x01\x01\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x01\x00\x00\x00"
        # find the first header
        pos = self.blob.find(sigstruct_header)
        if pos != -1:
            # check the second header, 8 bytes after the first one
            if self.blob[pos+24:][:16] == sigstruct_header2:
                # we did a match, return pos
                return pos
        return None

    # as found in 64 bit platform enclaves
    def find_ecalls_offset(self):
        # NOTE: this is a best effort heuristic to extract ECALLs table
        #       memory address. It's based on manual analysis and rely
        #    on finding the right things at the expected place.
        ecalls_magic = "\x44\x49\x43\x4f"
        # it's usually located in more than one place
        pos = 0
        while True:
            pos = self.blob.find(ecalls_magic, pos+4)
            if pos == -1:
                break
            # skip danger zone
            pos += 16
            # find mov opcode in next 32 bytes (488b15xxxxxxxx)
            # movpos = self.blob.find("\x48\x8b\x15", pos, pos+32)
            movpos = self.blob.find("\x48\x8b", pos, pos+32)
            # we have a match!
            if movpos != -1:
                # extract address offset from mov opcode
                offset, = unpack("<I", self.blob[movpos+3:movpos+7])
                # add seven (instruction offset counts from next inst)
                offset += 7
                # find instruction virtual addr
                ivaddr = self.get_vaddr(movpos)
                # apply table offset
                tvaddr = ivaddr+offset
                # return table raw addr
                return self.get_raddr(tvaddr)
        return None

    # as found in 32 bit debug enclaves
    def find_ecalls_debug(self):
        # NOTE: this is a best effort heuristic to extract ECALLs table
        #       memory address. It's based on manual analysis and rely
        #    on finding the right things at the expected place.
        ecalls_magic = "\x44\x49\x43\x4f"
        # it's usually located in more than one place
        pos = 0
        while True:
            pos = self.blob.find(ecalls_magic, pos+4)
            if pos == -1:
                break
            # find mov opcode in next 32 bytes (488b15xxxxxxxx)
            movpos = self.blob.find("\xa1", pos, pos+48)
            # we have a match!
            if movpos != -1:
                # extract table virtual addr from mov opcode
                tvaddr, = unpack("<I", self.blob[movpos+1:movpos+5])
                # return table raw addr
                return self.get_raddr(tvaddr)
        return None

    # as found in 32 bit prerelease enclaves
    def find_ecalls_prerelease(self):
        # NOTE: this is a best effort heuristic to extract ECALLs table
        #       memory address. It's based on manual analysis and rely
        #    on finding the right things at the expected place.
        ecalls_magic = "\x44\x49\x43\x4f"
        # it's usually located in more than one place
        pos = 0
        while True:
            pos = self.blob.find(ecalls_magic, pos+4)
            if pos == -1:
                break
            # find mov opcode in next 32 bytes (488b15xxxxxxxx)
            movpos = self.blob.find("\x8b\x15", pos, pos+0x15)
            # we have a match!
            if movpos != -1:
                # extract table virtual addr from mov opcode
                tvaddr, = unpack("<I", self.blob[movpos+2:movpos+6])
                # return table raw addr
                return self.get_raddr(tvaddr)
        return None

    # as found in linux enclaves
    def find_ecalls_elf(self):
        t_section = None
        t_vaddr = None
        elf = ELFFile(open(self.filename, 'rb'))
        # find the symbols table(s)
        for section in elf.iter_sections():
            if section.header['sh_type'] == 'SHT_SYMTAB':
                # find the g_ecall_table symbol
                for symbol in section.iter_symbols():
                    if symbol.name == 'g_ecall_table':
                        t_section=symbol.entry['st_shndx']
                        t_vaddr=symbol.entry['st_value']
                        break
            if t_section and t_vaddr:
                break

        if t_section and t_vaddr:
            # we got it, go calculate the table address
            section = elf.get_section(t_section)
            # calculate the symbol offset from the section start
            sym_offset = t_vaddr - section.header['sh_addr']
            # return the physical address of the symbol
            return section.header['sh_offset'] + sym_offset

        return None


    def find_ecall_table(self):
        heuristics = [
            self.find_ecalls_offset,
            self.find_ecalls_prerelease,
            self.find_ecalls_debug,
            self.find_ecalls_elf
        ]

        for h in heuristics:
            try:
                pos = h()
                if pos:
                    return pos
            except:
                pass
        return None


    def ecalls_table(self, pos):
        ecalls = []
        # extract the number of ecalls
        n = unpack("<I", self.blob[pos:pos+4])[0]
        # iterate over the ecalls table to extract function addresses
        for i in range(n):
            if self.get_arch() == 32:
                # each address is a 32bit value after a 32 bit spacer
                fpos = pos+4+i*8
                # unpack 64bit vaddr
                vaddr, = unpack("<I", self.blob[fpos:fpos+4])
            if self.get_arch() == 64:
                # each address is a 64bit value after a 64 bit spacer
                fpos = pos+8+i*16
                # unpack 64bit vaddr
                vaddr = unpack("<I", self.blob[fpos:fpos+4])[0] + \
                    (unpack("<I", self.blob[fpos+4:fpos+8])[0]<<32)
            ecalls.append({'vaddr': vaddr})
        return ecalls


    def is_pe(self):
        # 1. Get PE signature offset (at 0xE0)
        sigpos, = unpack("<I", self.blob[0x3c:0x40])
        # check if the signature 'PE\0\0' is there
        return self.blob[sigpos:sigpos+4] == 'PE\0\0'

    def get_arch_elf(self):
        bits = None
        if self.blob[0x4] == '\x01':
            bits = 32
        elif self.blob[0x4] == '\x02':
            bits = 64
        return bits

    def get_arch_pe(self):
        bits = None
        # PE file format parsing!
        # 1. Get PE signature offset (at 0xE0)
        sigpos, = unpack("<I", self.blob[0x3c:0x40])
        # COFF header is immediately after signature
        coffpos = sigpos+4
        # Optional Header is located after COFF header (20bytes)
        optpos = coffpos+20
        # 32/64 bits?
        magic, = unpack("<H", self.blob[optpos:optpos+2])
        if magic == 0x10b:  # pe32
            bits = 32
        elif magic == 0x20b:  # pe32+
            bits = 64
        return bits

    def get_arch(self):
        if self.is_pe():
            return self.get_arch_pe()
        else:
            return self.get_arch_elf()
        return None


    def get_base(self):
        bits = self.get_arch()
        # PE file format parsing!
        # 1. Get PE signature offset (at 0xE0)
        sigpos, = unpack("<I", self.blob[0x3c:0x40])
        # COFF header is immediately after signature
        coffpos = sigpos+4
        # Optional Header is located after COFF header (20bytes)
        optpos = coffpos+20
        # 32/64 bits?
        if bits == 32:
            imagebase, = unpack("<I", self.blob[optpos+28:optpos+32])
        elif bits == 64:
            imagebase = unpack("<I", self.blob[optpos+24:optpos+28])[0] | \
                    (unpack("<I", self.blob[optpos+28:optpos+32])[0]<<32)
        else:
            imagebase = None

        return imagebase

    def get_sections(self):
        sections = []
        base = self.get_base()
        # PE file format parsing!
        # 1. Get PE signature offset (at 0xE0)
        sigpos, = unpack("<I", self.blob[0x3c:0x40])
        # COFF header is immediately after signature
        coffpos = sigpos+4
        # Get # of sections
        nsections, = unpack("<H", self.blob[coffpos+2:coffpos+4])
        # Get Optional Header size (as sections are located after it)
        optsize, = unpack("<H", self.blob[coffpos+16:coffpos+18])
        # Optional Header is located after COFF header (20bytes)
        optpos = coffpos+20
        # Sections are located after optional headers
        sectpos = optpos+optsize
        # parse sections
        for n in range(nsections):
            # Section size = 40bytes
            spos = sectpos+n*40
            # Extract attributes
            name = self.blob[spos:spos+8]
            # Extract Virtual info
            vsize, vaddr = unpack("<II", self.blob[spos+8:spos+16])
            # Extract raw info
            rsize, raddr = unpack("<II", self.blob[spos+16:spos+24])
            sections.append({
                'name': name,
                'vsize': vsize,
                'vaddr': base+vaddr,
                'rsize': rsize,
                'raddr': raddr
            })
        return sections


    def get_vaddr(self, raddr):
        for section in self.get_sections():
            if raddr >= section['raddr'] and raddr < section['raddr'] + section['rsize']:
                return raddr - section['raddr'] + section['vaddr']
        return None

    def get_raddr(self, vaddr):
        for section in self.get_sections():
            if vaddr >= section['vaddr'] and \
               vaddr < section['vaddr'] + section['rsize']:
                return vaddr - section['vaddr'] + section['raddr']
        return None


    def size(self):
        return len(self.blob)

    def sgxmeta(self, pos):
        values = []
        values.append(('header', self.blob[pos:][:16]))
        values.append(('struct_size', unpack("<I", self.blob[pos+16:][:4])[0]))
        values.append(('threads', unpack("<I", self.blob[pos+20:][:4])[0]))
        values.append(('tls_field_8', self.blob[pos+24:][:4]))
        values.append(('tcs_nnsa', self.blob[pos+28:][:4]))
        values.append(('unknown', self.blob[pos+32:][:4]))
        values.append(('stack_size', unpack("<I", self.blob[pos+36:][:4])[0]))
        values.append(('heap_size', unpack("<I", self.blob[pos+40:][:4])[0]))
        values.append(('unknown', self.blob[pos+44:][:4]))
        values.append(('unknown', self.blob[pos+48:][:4]))
        values.append(('request_attrs', self.blob[pos+52:][:16]))
        values.append(('request_attrs_xfrm', self.blob[pos+68:][:16]))
        return values


    def sigstruct(self, pos):
        size = 1808
        # grab sigstruct array
        arr = self.blob[pos:][:size]
        # grab values
        values = []
        values.append(('header', arr[0:16]))
        values.append(('vendor', arr[16:16+4][::-1]))
        values.append(('date', arr[20:20+4][::-1]))
        values.append(('header2', arr[24:24+16]))
        values.append(('swdefined', arr[40:40+4]))
        values.append(('reserved', arr[44:44+84]))

        nbytes = arr[128:128+384][::-1]
        n = int(hexlify(nbytes), 16)
        values.append(('modulus', n))

        ebytes = arr[512:512+4][::-1]
        e = int(hexlify(ebytes), 16)
        values.append(('exponent', e))

        sbytes = arr[516:516+384][::-1]
        s = int(hexlify(sbytes), 16)
        values.append(('signature', s))

        values.append(('miscselect', arr[900:900+4]))
        values.append(('miscmask', arr[904:904+4]))
        values.append(('reserved', arr[908:908+20]))
        values.append(('attributes', arr[928:928+16]))
        values.append(('attributemask', arr[944:944+16]))
        values.append(('enclavehash', arr[960:960+32]))
        values.append(('reserved', arr[992:992+32]))
        values.append(('isvprodid', arr[1024:1024+2][::-1]))
        values.append(('isvsvn', arr[1026:1026+2][::-1]))
        values.append(('reserved', arr[1024:1024+12]))

        q1bytes = arr[1040:1040+384][::-1]
        q1 = int(hexlify(q1bytes), 16)

        q2bytes = arr[1424:1424+384][::-1]
        q2 = int(hexlify(q2bytes), 16)

        if not rsa_check(n, s, q1, q2):
            print('RSA parameters invalid')

        values.append(('q1', q1))
        values.append(('q2', q2))
        return values

    def attributes(self, blob):
        attributes_size = 16
        # check size
        if len(blob) != attributes_size:
            return None
        # grab values
        fields = []
        fields.append(('reserved', ord(blob[0])&1))
        fields.append(('debug', ord(blob[0])>>1&1))
        fields.append(('mode64bit', ord(blob[0])>>2&1))
        fields.append(('reserved', ord(blob[0])>>3&1))
        fields.append(('provisionkey', ord(blob[0])>>4&1))
        fields.append(('einitokenkey', ord(blob[0])>>5&1))
        # reserved? bits 6:63
        fields.append(('xfrm', blob[8:]))
        return fields


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=None)
    parser.add_argument('filename', type=str,
                        help="Signed enclave filename")
    parser.add_argument('--only-mr-enclave', action='store_true',
                        help="Only output MRENCLAVE")
    args = parser.parse_args()

    fname = args.filename
    p = Parser(fname)

    if args.only_mr_enclave:
        # Only output MRENCLAVE.
        sigstruct_pos = p.find_sigstruct_header()
        sigstruct = p.sigstruct(sigstruct_pos)
        mr_enclave = [v for k, v in sigstruct if k == 'enclavehash'][0]
        sys.stdout.write(mr_enclave)
        sys.exit(0)

    print('Enclave file: %s' % fname)
    print('Enclave size: %d bytes' % p.size())
    sigstruct_pos = p.find_sigstruct_header()
    if sigstruct_pos:
        print('SIGSTRUCT found at %s' % hex(sigstruct_pos))
    else:
        print('SIGSTRUCT not found. trying with weak header')
        sigstruct_pos = p.find_weak_sigstruct_header()
        if sigstruct_pos:
            print('Weak sigstruct found at 0x%s' % hex(sigstruct_pos))
        else:
            sys.exit(1)

    sigstruct = p.sigstruct(sigstruct_pos)
    # print sigstruct
    for k, v in sigstruct:
        if isinstance(v, (bytes)):
            print("%20s\t%s" % (k.upper(), hexlify(v)))
        else:
            print("%20s\t%d" % (k.upper(), v))

    print('\n')
    print('# ATTRIBUTES\n')
    attrs = p.attributes(sigstruct[12][1])
    # print attributes
    print('%20s\t%d' % ('DEBUG', attrs[1][1]))
    print('%20s\t%d' % ('MODE64BIT', attrs[2][1]))
    print('%20s\t%d' % ('PROVISIONKEY', attrs[4][1]))
    print('%20s\t%d' % ('EINITTOKEN', attrs[5][1]))

    # now, let's parse sgxmeta section
    sgxmeta_pos = p.find_sgxmeta_header()
    if sgxmeta_pos:
        sgxmeta = p.sgxmeta(sgxmeta_pos)
        print('\n# sgxmeta found at 0x%s\n' % hex(sgxmeta_pos))
        for k, v in sgxmeta:
            if isinstance(v, (long, int)):
                print('%20s\t%d' % (k.upper(), v))
            else:
                print('%20s\t%s' % (k.upper(), hexlify(v)))
    else:
        print('\n# sgxmeta not found')

    # locating ECALLs table
    epos = p.find_ecall_table()
    if epos:
        print('\n# ECALLs table found at 0x%x' % epos)
        necalls, = unpack("<I", p.blob[epos:epos+4])
        # extract ecall table
        ecalls = p.ecalls_table(epos)
        # parse ecalls table
        for i in range(len(ecalls)):
            print('%20d\tvaddr: 0x%x' % (i, ecalls[i]['vaddr']))
    else:
        print('\n# ECALLs table not found')


