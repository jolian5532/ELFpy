import sys
import struct

class ElfFile:
    def __init__(self, file_path):
        self.readFromFile(file_path)
        
    def getBytes(self,start, nbytes,x=0):
        if not x:
            return self.lend(self.file_data[start:start+nbytes])
        else:
            return self.file_data[start:start+nbytes]
    
    def readFromFile(self, file):
        f = open(file, "rb")
        self.file_data = f.read()

    def lend(self,bytes):
        return bytes[::-1]

    def deser(self):
        self.e_ident = self.getBytes(0,16)      # File ident
        self.EI_IMG = self.getBytes(0,4)        # ELF Signature
        self.EI_CLASS = self.getBytes(4,2)      # 64Bit , Endian
        self.EI_VERSION = self.getBytes(6,4)    # Always 1
        self.e_type = self.getBytes(16, 2)      # Obj/File type
        self.e_machine = self.getBytes(18, 2)   # ARCH
        self.e_version = self.getBytes(20, 4)   # ELF version (1)
        self.e_entry = self.getBytes(24, 8)     # Entry point
        self.e_phoff = self.getBytes(32, 8)     # Program header offset
        self.e_shoff = self.getBytes(40, 8)     # Section header offset
        self.e_flags = self.getBytes(48, 4)     # ARCH flags
        self.e_ehsize = self.getBytes(52, 2)    # Size of ELF header in Bytes
        self.e_phentsize = self.getBytes(54, 2) # Size of program header entry
        self.e_phnum = self.getBytes(56, 2)     # Number of program header entries
        self.e_shentsize = self.getBytes(58, 2) # Size of section header entry
        self.e_shnum = self.getBytes(60, 2)     # Number of section header entries
        self.e_shstrndx = self.getBytes(62, 2)  # Section name strings section
    def print_header(self):
        print(f"e_ident: {self.e_ident.hex()}")
        print(f"EI_IMG: {self.EI_IMG.hex()}")
        print(f"EI_CLASS: {self.EI_CLASS.hex()}")
        print(f"EI_VERSION: {self.EI_VERSION.hex()}")
        print(f"e_type: {self.e_type.hex()}")
        print(f"e_machine: {self.e_machine.hex()}")
        print(f"e_version: {self.e_version.hex()}")
        print(f"e_entry: {self.e_entry.hex()}")
        print(f"e_phoff: {self.e_phoff.hex()}")
        print(f"e_shoff: {self.e_shoff.hex()}")
        print(f"e_flags: {self.e_flags.hex()}")
        print(f"e_ehsize: {self.e_ehsize.hex()}")
        print(f"e_phentsize: {self.e_phentsize.hex()}")
        print(f"e_phnum: {self.e_phnum.hex()}")
        print(f"e_shentsize: {self.e_shentsize.hex()}")
        print(f"e_shnum: {self.e_shnum.hex()}")
        print(f"e_shstrndx: {self.e_shstrndx.hex()}")

    def getPHeaders(self):
        self.PHeaders = []
        headersBegin = int.from_bytes(self.e_phoff, "big")
        headersSize = int.from_bytes(self.e_phentsize, "big") * int.from_bytes(self.e_phnum, "big")
        return [self.getBytes(headersBegin,headersSize,1)[i:i+int.from_bytes(self.e_phentsize, "big")] for i in range(0, len(self.getBytes(headersBegin,headersSize,1)), int.from_bytes(self.e_phentsize, "big"))]
        
    
a  = ElfFile(str(sys.argv[1]))
a.deser()
print(a.getPHeaders()[0].hex())