import sys
import json


class ElfFile:
    def __init__(self, file_path):
        self.readFromFile(file_path)

    def getBytes(self, start, nbytes, x=0):
        if x == 0:
            return self.file_data[start : start + nbytes]
        else:
            return x[start : start + nbytes]

    def readFromFile(self, file):
        f = open(file, "rb")
        self.file_data = f.read()

    def lend(self, bytes):
        return bytes[::-1]

    def deser(self):
        self.elffile64 = {
            "e_ident": {
                "offset": 0,
                "size": 16,  # in bytes
                "description": "ELF Identification",
                "value": self.getBytes(0, 16),
                "readValue": self.lend(self.getBytes(0, 16)).hex(),
            },
            "EI_IMG": {
                "offset": 0,
                "size": 4,
                "description": "ELF Signature",
                "value": self.getBytes(0, 4),
                "readValue": self.lend(self.getBytes(0, 4)).hex(),
            },
            "EI_CLASS": {
                "offset": 4,
                "size": 2,
                "description": "64Bit , Endian",
                "value": self.getBytes(4, 2),
                "readValue": self.lend(self.getBytes(4, 2)).hex(),
            },
            "EI_VERSION": {
                "offset": 6,
                "size": 4,
                "description": "Always 1",
                "value": self.getBytes(6, 4),
                "readValue": self.lend(self.getBytes(6, 4)).hex(),
            },
            "e_type": {
                "offset": 16,
                "size": 2,
                "description": "Obj/File type",
                "value": self.getBytes(16, 2),
                "readValue": self.lend(self.getBytes(16, 2)).hex(),
            },
            "e_machine": {
                "offset": 18,
                "size": 2,
                "description": "ARCH",
                "value": self.getBytes(18, 2),
                "readValue": self.lend(self.getBytes(18, 2)).hex(),
            },
            "e_version": {
                "offset": 20,
                "size": 4,
                "description": "ELF version (1)",
                "value": self.getBytes(20, 4),
                "readValue": self.lend(self.getBytes(20, 4)).hex(),
            },
            "e_entry": {
                "offset": 24,
                "size": 8,
                "description": "Entry point",
                "value": self.getBytes(24, 8),
                "readValue": self.lend(self.getBytes(24, 8)).hex(),
            },
            "e_phoff": {
                "offset": 32,
                "size": 8,
                "description": "Program header offset",
                "value": self.getBytes(32, 8),
                "readValue": self.lend(self.getBytes(32, 8)).hex(),
            },
            "e_shoff": {
                "offset": 40,
                "size": 8,
                "description": "Section header offset",
                "value": self.getBytes(40, 8),
                "readValue": self.lend(self.getBytes(40, 8)).hex(),
            },
            "e_flags": {
                "offset": 48,
                "size": 4,
                "description": "ARCH flags",
                "value": self.getBytes(48, 4),
                "readValue": self.lend(self.getBytes(48, 4)).hex(),
            },
            "e_ehsize": {
                "offset": 52,
                "size": 2,
                "description": "Size of ELF header in Bytes",
                "value": self.getBytes(52, 2),
                "readValue": self.lend(self.getBytes(52, 2)).hex(),
            },
            "e_phentsize": {
                "offset": 54,
                "size": 2,
                "description": "Size of program header entry",
                "value": self.getBytes(54, 2),
                "readValue": self.lend(self.getBytes(54, 2)).hex(),
            },
            "e_phnum": {
                "offset": 56,
                "size": 2,
                "description": "Number of program header entries",
                "value": self.getBytes(56, 2),
                "readValue": self.lend(self.getBytes(56, 2)).hex(),
            },
            "e_shentsize": {
                "offset": 58,
                "size": 2,
                "description": "Size of section header entry",
                "value": self.getBytes(58, 2),
                "readValue": self.lend(self.getBytes(58, 2)).hex(),
            },
            "e_shnum": {
                "offset": 60,
                "size": 2,
                "description": "Number of section header entries",
                "value": self.getBytes(60, 2),
                "readValue": self.lend(self.getBytes(60, 2)).hex(),
            },
            "e_shstrndx": {
                "offset": 62,
                "size": 2,
                "description": "Section name strings section",
                "value": self.getBytes(62, 2),
                "readValue": self.lend(self.getBytes(62, 2)).hex(),
            },
            "PHeaders": [],
        }

        # Construct Program Headers
        PHeadersOffset = int(self.elffile64["e_phoff"]["readValue"], 16)
        PHeaderSize = int(self.elffile64["e_phentsize"]["readValue"], 16)
        PHeadersAmount = int(self.elffile64["e_phnum"]["readValue"], 16)
        PHeaders = self.getBytes(PHeadersOffset, PHeaderSize * PHeadersAmount)
        PHeaders = [
            PHeaders[i : i + PHeaderSize] for i in range(0, len(PHeaders), PHeaderSize)
        ]
        for index, PHeader in enumerate(PHeaders):
            header_entry = {
                "index": {
                    "value": index,
                    "readValue": index,
                },
                "p-type": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 0,
                    "size": 4,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 0, 4
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 0, 4)
                    ).hex(),
                    "description": "Segment Type",
                },
                "p-flags": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 4,
                    "size": 4,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 4, 4
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 4, 4)
                    ).hex(),
                    "description": "Segment Flags",
                },
                "p-offset": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 8,
                    "size": 8,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 8, 8
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 8, 8)
                    ).hex(),
                    "description": "Segment Offset",
                },
                "p-vaddr": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 16,
                    "size": 8,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 16, 8
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 16, 8)
                    ).hex(),
                    "description": "Segment Virtual Address",
                },
                "p-paddr": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 24,
                    "size": 8,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 24, 8
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 24, 8)
                    ).hex(),
                    "description": "Segment Physical Address",
                },
                "p-filesz": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 32,
                    "size": 8,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 32, 8
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 32, 8)
                    ).hex(),
                    "description": "Segment File Size",
                },
                "p-memsz": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 40,
                    "size": 8,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 40, 8
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 40, 8)
                    ).hex(),
                    "description": "Segment Memory Size",
                },
                "p-align": {
                    "offset": (index * PHeaderSize) + PHeadersOffset + 48,
                    "size": 8,
                    "value": self.getBytes(
                        (index * PHeaderSize) + PHeadersOffset + 48, 8
                    ),
                    "readValue": self.lend(
                        self.getBytes((index * PHeaderSize) + PHeadersOffset + 48, 8)
                    ).hex(),
                    "description": "Segment Alignment",
                },
            }
            self.elffile64[f"PHeaders"].append(header_entry)


a = ElfFile(str(sys.argv[1]))

a.deser()
# for key, value in a.elffile64.items():
#   print(value["description"] + " : " + str(value["readValue"]))

print(a.elffile64["PHeaders"][2])
