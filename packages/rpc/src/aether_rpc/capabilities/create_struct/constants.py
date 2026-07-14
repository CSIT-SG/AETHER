import ida_typeinf

TYPE_MAP = {
    "uint8_t": ida_typeinf.BTF_UINT8,
    "uint16_t": ida_typeinf.BTF_UINT16,
    "uint32_t": ida_typeinf.BTF_UINT32,
    "uint64_t": ida_typeinf.BTF_UINT64,
    "int8_t": ida_typeinf.BTF_INT8,
    "int16_t": ida_typeinf.BTF_INT16,
    "int32_t": ida_typeinf.BTF_INT32,
    "int64_t": ida_typeinf.BTF_INT64,
    "char": ida_typeinf.BTF_CHAR,
    "bool": ida_typeinf.BTF_BOOL,
    "byte": ida_typeinf.BTF_BYTE,
    "float": ida_typeinf.BTF_FLOAT,
    "double": ida_typeinf.BTF_DOUBLE,
    "void": ida_typeinf.BTF_VOID,
}
