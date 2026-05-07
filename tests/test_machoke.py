from binrankbench.modules.machoke import fcode_to_machoke_line, fcode_to_machoke_hash
from binrankbench.common.types import R2CodeInfoIn
from binrankbench.common.hex import HexStr


#region FIXTURES

# From the official specification example at
# https://github.com/ANSSI-FR/polichombr/blob/dev/docs/MACHOC_HASH.md
test_machoke_hash = "0x1014997f"
test_line = "1:2,3;2:;3:4,10;4:6;5:6;6:c,7;7:c,8;8:5,9;9:10;10:;"
# The dictionary below was generated from the documentation's CFG example.
test_fcode: R2CodeInfoIn = {
    "name": "sym.machoc_example",
    "nargs": 0,
    "ninstr": 20,
    "nlocals": 0,
    "offset": 0x1000,
    "size": 0x200,
    "stack": 0,
    "type": "fcn",
    "blocks": [
        # 1 -> 2,3
        {
            "offset": 0x1000, "size": 10, "jump": 0x1020, "fail": 0x1010,
            "ops": [
                {
                    "offset": 0x1000, "size": 5, "type": "cmp",
                    "bytes": "3945fc", "family": "cpu",
                    "disasm": "cmp dword [rbp - 4], eax",
                    "opcode": "cmp [rbp - 4], eax",
                    "esil": "eax,rbp,0x4,-,[4],==,$z,zf,:="
                },
                {
                    "offset": 0x1005, "size": 5, "type": "cjmp",
                    "bytes": "7419", "family": "cpu",
                    "disasm": "je 0x1020",
                    "opcode": "if (zf) goto 0x1020",
                    "esil": "zf,?{,0x1020,rip,=,}",
                    "jump": 0x1020, "fail": 0x1010,
                    "refs": [{"addr": 0x1020, "perm": "--x", "type": "CODE"}]
                }
            ]
        },
        # 2 terminal
        {
            "offset": 0x1010, "size": 10,
            "ops": [
                {
                    "offset": 0x1010, "size": 5, "type": "mov",
                    "bytes": "b800000000", "family": "cpu",
                    "disasm": "mov eax, 0",
                    "opcode": "eax = 0",
                    "esil": "0,rax,="
                },
                {
                    "offset": 0x1015, "size": 1, "type": "ret",
                    "bytes": "c3", "family": "cpu",
                    "disasm": "ret",
                    "opcode": "ret",
                    "esil": "rsp,[8],rip,=,8,rsp,+="
                }
            ]
        },
        # 3 -> 4,10
        {
            "offset": 0x1020, "size": 10, "jump": 0x1050, "fail": 0x1030,
            "ops": [
                {
                    "offset": 0x1020, "size": 5, "type": "cmp",
                    "bytes": "837dfc01", "family": "cpu",
                    "disasm": "cmp dword [rbp - 4], 1",
                    "opcode": "cmp [rbp - 4], 1",
                    "esil": "1,rbp,0x4,-,[4],==,$z,zf,:="
                },
                {
                    "offset": 0x1025, "size": 5, "type": "cjmp",
                    "bytes": "7429", "family": "cpu",
                    "disasm": "je 0x1050",
                    "opcode": "if (zf) goto 0x1050",
                    "esil": "zf,?{,0x1050,rip,=,}",
                    "jump": 0x1050, "fail": 0x1030,
                    "refs": [{"addr": 0x1050, "perm": "--x", "type": "CODE"}]
                }
            ]
        },
        # 4 -> 6
        {
            "offset": 0x1030, "size": 5, "jump": 0x103A,
            "ops": [
                {
                    "offset": 0x1030, "size": 5, "type": "jmp",
                    "bytes": "e9", "family": "cpu",
                    "disasm": "jmp 0x103a",
                    "opcode": "goto 0x103a",
                    "esil": "0x103a,rip,="
                }
            ]
        },
        # 5 -> 6
        {
            "offset": 0x1035, "size": 5, "jump": 0x103A,
            "ops": [
                {
                    "offset": 0x1035, "size": 5, "type": "jmp",
                    "bytes": "e9", "family": "cpu",
                    "disasm": "jmp 0x103a",
                    "opcode": "goto 0x103a",
                    "esil": "0x103a,rip,="
                }
            ]
        },
        # 6: direct CALL ; fallthrough -> 7
        {
            "offset": 0x103A, "size": 5, "fail": 0x103F,
            "ops": [
                {
                    "offset": 0x103A, "size": 5, "type": "call",
                    "bytes": "e800000000", "family": "cpu",
                    "disasm": "call 0x2000",
                    "opcode": "call 0x2000",
                    "esil": "rip,8,rsp,-=,rsp,=[8],0x2000,rip,=",
                    "refs": [{"addr": 0x2000, "perm": "--x", "type": "CALL"}]
                }
            ]
        },
        # 7: direct CALL ; fallthrough -> 8
        {
            "offset": 0x103F, "size": 5, "fail": 0x1044,
            "ops": [
                {
                    "offset": 0x103F, "size": 5, "type": "call",
                    "bytes": "e800000000", "family": "cpu",
                    "disasm": "call 0x3000",
                    "opcode": "call 0x3000",
                    "esil": "rip,8,rsp,-=,rsp,=[8],0x3000,rip,=",
                    "refs": [{"addr": 0x3000, "perm": "--x", "type": "CALL"}]
                }
            ]
        },
        # 8 -> 5,9
        {
            "offset": 0x1044, "size": 10, "jump": 0x1035, "fail": 0x104E,
            "ops": [
                {
                    "offset": 0x1044, "size": 5, "type": "cmp",
                    "bytes": "837dfc0a", "family": "cpu",
                    "disasm": "cmp dword [rbp - 4], 10",
                    "opcode": "cmp [rbp - 4], 10",
                    "esil": "10,rbp,0x4,-,[4],==,$z,zf,:="
                },
                {
                    "offset": 0x1049, "size": 5, "type": "cjmp",
                    "bytes": "7c0a", "family": "cpu",
                    "disasm": "jl 0x1035",
                    "opcode": "if (<) goto 0x1035",
                    "esil": "sf,?{,0x1035,rip,=,}",
                    "jump": 0x1035, "fail": 0x104E,
                    "refs": [{"addr": 0x1035, "perm": "--x", "type": "CODE"}]
                }
            ]
        },
        # 9 -> 10
        {
            "offset": 0x104E, "size": 5, "jump": 0x1050,
            "ops": [
                {
                    "offset": 0x104E, "size": 5, "type": "jmp",
                    "bytes": "e9", "family": "cpu",
                    "disasm": "jmp 0x1050",
                    "opcode": "goto 0x1050",
                    "esil": "0x1050,rip,="
                }
            ]
        },
        # 10 terminal
        {
            "offset": 0x1050, "size": 6,
            "ops": [
                {
                    "offset": 0x1050, "size": 5, "type": "mov",
                    "bytes": "8b45fc", "family": "cpu",
                    "disasm": "mov eax, dword [rbp - 4]",
                    "opcode": "eax = [rbp - 4]",
                    "esil": "rbp,0x4,-,[4],rax,="
                },
                {
                    "offset": 0x1055, "size": 1, "type": "ret",
                    "bytes": "c3", "family": "cpu",
                    "disasm": "ret",
                    "opcode": "ret",
                    "esil": "rsp,[8],rip,=,8,rsp,+="
                }
            ]
        }
    ]
}

test_fcode_multiple_calls: R2CodeInfoIn = {
    "name": "sym.machoc_multiple_calls",
    "nargs": 0,
    "ninstr": 20,
    "nlocals": 0,
    "offset": 0x1000,
    "size": 0x200,
    "stack": 0,
    "type": "fcn",
    "blocks": [
        # 1 -> 2,3
        {
            "offset": 0x1000, "size": 10, "jump": 0x103A, "fail": 0x1044,
            "ops": [
                {
                    "offset": 0x1000, "size": 5, "type": "cmp",
                    "bytes": "3945fc", "family": "cpu",
                    "disasm": "cmp dword [rbp - 4], eax",
                    "opcode": "cmp [rbp - 4], eax",
                    "esil": "eax,rbp,0x4,-,[4],==,$z,zf,:="
                },
                {
                    "offset": 0x1005, "size": 5, "type": "cjmp",
                    "bytes": "7419", "family": "cpu",
                    "disasm": "je 0x1020",
                    "opcode": "if (zf) goto 0x1020",
                    "esil": "zf,?{,0x1020,rip,=,}",
                    "jump": 0x1020, "fail": 0x1010,
                    "refs": [{"addr": 0x103A, "perm": "--x", "type": "CODE"}]
                }
            ]
        },
        {
            "offset": 0x103A, "size": 10, "fail": 0x1044,
            "ops": [
                {
                    "offset": 0x103A, "size": 5, "type": "call",
                    "bytes": "e800000000", "family": "cpu",
                    "disasm": "call 0x2000",
                    "opcode": "call 0x2000",
                    "esil": "rip,8,rsp,-=,rsp,=[8],0x2000,rip,=",
                    "refs": [{"addr": 0x2000, "perm": "--x", "type": "CALL"}]
                },
                {
                    "offset": 0x103F, "size": 5, "type": "call",
                    "bytes": "e800000000", "family": "cpu",
                    "disasm": "call 0x3000",
                    "opcode": "call 0x3000",
                    "esil": "rip,8,rsp,-=,rsp,=[8],0x3000,rip,=",
                    "refs": [{"addr": 0x3000, "perm": "--x", "type": "CALL"}]
                }
            ]
        },
        {
            "offset": 0x1044, "size": 6,
            "ops": [
                {
                    "offset": 0x1044, "size": 5, "type": "mov",
                    "bytes": "8b45fc", "family": "cpu",
                    "disasm": "mov eax, dword [rbp - 4]",
                    "opcode": "eax = [rbp - 4]",
                    "esil": "rbp,0x4,-,[4],rax,="
                },
                {
                    "offset": 0x1049, "size": 1, "type": "ret",
                    "bytes": "c3", "family": "cpu",
                    "disasm": "ret",
                    "opcode": "ret",
                    "esil": "rsp,[8],rip,=,8,rsp,+="
                }
            ]
        }
    ]
}
#endregion FIXTURES


def test_fcode_to_machoke_line():
    line = fcode_to_machoke_line(test_fcode)
    assert line == test_line
    
def test_fcode_to_machoke_hash():
    machoke_hash = fcode_to_machoke_hash(test_fcode)
    assert machoke_hash == test_machoke_hash

def test_fcode_to_machoke_hash_multiple_calls():
    machoke_line_with_split = fcode_to_machoke_line(test_fcode_multiple_calls,
                                                    split_on_calls=True)
    machoke_line_no_split = fcode_to_machoke_line(test_fcode_multiple_calls, 
                                                  split_on_calls=False)
    
    assert machoke_line_no_split != machoke_line_with_split
