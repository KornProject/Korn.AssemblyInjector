static class OpCodes
{
    public static readonly byte Ret = 0xC3;
    public static readonly byte ShortJump = 0xEB;
    public static readonly byte Relative32Jump = 0xE9;
    public static readonly byte RelativeCall = 0xE8;

    public static readonly byte PushRbx = 0x53;
    public static readonly byte PushRdi = 0x57;
    public static readonly byte PushRsi = 0x56;
    public static readonly byte PushRdx = 0x52;
    public static readonly byte PushRcx = 0x51;
    public static readonly byte[] PushR8 = [0x41, 0x50];
    public static readonly byte[] PushR9 = [0x41, 0x51];

    public static readonly byte[] PushRel8Rsp = [0xFF, 0x74, 0x24];
    public static readonly byte[] PushRel32Rsp = [0xFF, 0xB4, 0x24];

    public static readonly byte PopRbx = 0x5B;
    public static readonly byte PopRdi = 0x5F;
    public static readonly byte PopRsi = 0x5E;
    public static readonly byte PopRdx = 0x5A;
    public static readonly byte PopRcx = 0x59;
    public static readonly byte[] PopR8 = [0x41, 0x58];
    public static readonly byte[] PopR9 = [0x41, 0x59];

    public static readonly byte[] Mov32Rax = [0x48, 0xC7, 0xC0];
    public static readonly byte[] Mov32Rbx = [0x48, 0xC7, 0xC3];
    public static readonly byte[] Mov32Rdi = [0x48, 0xC7, 0xC7];
    public static readonly byte[] Mov32Rsi = [0x48, 0xC7, 0xC6];
    public static readonly byte[] Mov32Rdx = [0x48, 0xC7, 0xC2];
    public static readonly byte[] Mov32Rcx = [0x48, 0xC7, 0xC1];
    public static readonly byte[] Mov32R8 = [0x49, 0xC7, 0xC0];
    public static readonly byte[] Mov32R9 = [0x49, 0xC7, 0xC1];
    public static readonly byte[] Mov64Rax = [0x48, 0xB8];
    public static readonly byte[] Mov64Rbx = [0x48, 0xBB];
    public static readonly byte[] Mov64Rdi = [0x48, 0xBF];
    public static readonly byte[] Mov64Rsi = [0x48, 0xBE];
    public static readonly byte[] Mov64Rdx = [0x48, 0xBA];
    public static readonly byte[] Mov64Rcx = [0x48, 0xB9];
    public static readonly byte[] Mov64R8 = [0x49, 0xB8];
    public static readonly byte[] Mov64R9 = [0x49, 0xB9];

    public static readonly byte[] JumpRax = [0xFF, 0xE0];
    public static readonly byte[] CallRax = [0xFF, 0xD0];

    public static readonly byte[] Sub32Rsp = [0x48, 0x81, 0xEC];

    public static readonly byte[] Sub8Rsp = [0x48, 0x83, 0xEC];

    public static readonly byte[] Add32Rsp = [0x48, 0x81, 0xC4];
    public static readonly byte[] Add32Rbx = [0x48, 0x81, 0xC3];

    public static readonly byte[] Add8Rsp = [0x48, 0x83, 0xC4];
    public static readonly byte[] Add8Rbx = [0x48, 0x83, 0xC3];

    public static readonly byte[] Mov32Rel8Rsp = [0x48, 0xC7, 0x44, 0x24];
    public static readonly byte[] Mov32Rel32Rsp = [0x48, 0xC7, 0x84, 0x24];

    public static readonly byte[] MovRel8RspRdi = [0x48, 0x8B, 0x7C, 0x24];
    public static readonly byte[] MovRel8RspRsi = [0x48, 0x8B, 0x74, 0x24];
    public static readonly byte[] MovRel8RspRdx = [0x48, 0x8B, 0x54, 0x24];
    public static readonly byte[] MovRel8RspRcx = [0x48, 0x8B, 0x4C, 0x24];
    public static readonly byte[] MovRel8RspR8 = [0x4C, 0x8B, 0x44, 0x24];
    public static readonly byte[] MovRel8RspR9 = [0x4C, 0x8B, 0x4C, 0x24];
    public static readonly byte[] MovRel8RspRbx = [0x48, 0x8B, 0x5C, 0x24];
    public static readonly byte[] MovRel8RspRax = [0x48, 0x8B, 0x44, 0x24];
    public static readonly byte[] MovRel32RspRdi = [0x48, 0x8B, 0xBC, 0x24];
    public static readonly byte[] MovRel32RspRsi = [0x48, 0x8B, 0xB4, 0x24];
    public static readonly byte[] MovRel32RspRdx = [0x48, 0x8B, 0x94, 0x24];
    public static readonly byte[] MovRel32RspRcx = [0x48, 0x8B, 0x8C, 0x24];
    public static readonly byte[] MovRel32RspR8 = [0x4C, 0x8B, 0x84, 0x24];
    public static readonly byte[] MovRel32RspR9 = [0x4C, 0x8B, 0x8C, 0x24];
    public static readonly byte[] MovRel32RspRbx = [0x48, 0x8B, 0x9C, 0x24];
    public static readonly byte[] MovRel32RspRax = [0x48, 0x8B, 0x84, 0x24];

    public static readonly byte[] MovRspRbx = [0x48, 0x89, 0xE3];

    public static readonly byte[] MovRbxRel8Rsp = [0x48, 0x89, 0x5C, 0x24];
    public static readonly byte[] MovRbxRel32Rsp = [0x48, 0x89, 0x9C, 0x24];
}