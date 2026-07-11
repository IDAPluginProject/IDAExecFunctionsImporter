#!/usr/bin/env python3
"""Tkinter visualizer for Dumper-7/IDAExecFunctionsImporter .idmap files."""

from __future__ import annotations

import argparse
import csv
import json
import os
import struct
import sys
import tkinter as tk
from dataclasses import asdict, dataclass, field
from tkinter import filedialog, messagebox, ttk
from typing import Any, Iterable


FILE_MAGIC = 0xD7
INVALID_STRING_OFFSET = 0xFFFFFFFF

HEADER = struct.Struct("<BBBIIIIIIIIIIII")
MEMBER = struct.Struct("<IIiii?B")
STRUCT_PREFIX = struct.Struct("<IIiii")
ENUM_PREFIX = struct.Struct("<IBi")
ENUM_VALUE = struct.Struct("<Iq")
EXEC_FUNC = struct.Struct("<IIIII")
EXEC_FUNC_LEGACY = struct.Struct("<IIII")
NAMED_VARIABLE = struct.Struct("<III")
NAMED_VTABLE = struct.Struct("<III")
STRING_LENGTH = struct.Struct("<H")
LEGACY_RECORD_PREFIX = struct.Struct("<IH")


@dataclass
class ParseIssue:
    severity: str
    message: str


@dataclass
class HeaderInfo:
    magic: int
    version: int
    reserved: int
    string_data_size_bytes: int
    string_data_offset: int
    num_enums: int
    enum_data_offset: int
    num_structs: int
    struct_data_offset: int
    num_global_symbols: int
    global_symbol_data_offset: int
    num_vtables: int
    vtable_data_offset: int
    num_exec_functions: int
    exec_function_data_offset: int


@dataclass
class MemberInfo:
    index: int
    type_offset: int
    type: str
    name_offset: int
    name: str
    offset: int
    size: int
    array_dim: int
    is_pointer: bool
    bitfield_bit_count: int


@dataclass
class StructInfo:
    index: int
    file_offset: int
    name_offset: int
    name: str
    super_name_offset: int
    super_name: str
    size: int
    alignment: int
    num_members: int
    data_end: int
    members: list[MemberInfo] = field(default_factory=list)


@dataclass
class EnumValueInfo:
    index: int
    name_offset: int
    name: str
    value: int


@dataclass
class EnumInfo:
    index: int
    file_offset: int
    name_offset: int
    name: str
    underlying_type_size_bytes: int
    num_values: int
    data_end: int
    values: list[EnumValueInfo] = field(default_factory=list)


@dataclass
class ExecFuncInfo:
    index: int
    file_offset: int
    mangled_name_offset: int
    mangled_name: str
    unmangled_name_offset: int
    unmangled_name: str
    offset_relative_to_imagebase: int
    cpp_type_signature_offset: int
    cpp_type_signature: str
    fallback_cpp_signature_info_offset: int
    fallback_cpp_signature_info: str


@dataclass
class NamedVariableInfo:
    index: int
    file_offset: int
    variable_offset: int
    type_offset: int
    type: str
    name_offset: int
    name: str


@dataclass
class NamedVTableInfo:
    index: int
    file_offset: int
    vtable_offset: int
    super_vtable_offset: int
    name_offset: int
    name: str


@dataclass
class StringEntry:
    index: int
    pool_offset: int
    absolute_offset: int
    length: int
    value: str


@dataclass
class LegacyRecord:
    index: int
    file_offset: int
    offset_relative_to_imagebase: int
    name: str


@dataclass
class MappingFile:
    path: str
    file_size: int
    format_name: str
    header: HeaderInfo | None = None
    issues: list[ParseIssue] = field(default_factory=list)
    strings: list[StringEntry] = field(default_factory=list)
    structs: list[StructInfo] = field(default_factory=list)
    enums: list[EnumInfo] = field(default_factory=list)
    exec_functions: list[ExecFuncInfo] = field(default_factory=list)
    global_symbols: list[NamedVariableInfo] = field(default_factory=list)
    vtables: list[NamedVTableInfo] = field(default_factory=list)
    legacy_records: list[LegacyRecord] = field(default_factory=list)

    def summary_rows(self) -> list[tuple[str, str]]:
        return [
            ("File", self.path),
            ("Format", self.format_name),
            ("Size", f"{self.file_size:,} bytes"),
            ("Version", str(self.header.version) if self.header else "-"),
            ("Strings", str(len(self.strings))),
            ("Structs", str(len(self.structs))),
            ("Enums", str(len(self.enums))),
            ("Exec functions", str(len(self.exec_functions))),
            ("Global symbols", str(len(self.global_symbols))),
            ("VTables", str(len(self.vtables))),
            ("Legacy records", str(len(self.legacy_records))),
            ("Issues", str(len(self.issues))),
        ]


class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data

    def can_read(self, offset: int, size: int) -> bool:
        return 0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset

    def unpack(self, fmt: struct.Struct, offset: int) -> tuple[Any, ...]:
        if not self.can_read(offset, fmt.size):
            raise ValueError(f"cannot read {fmt.size} bytes at 0x{offset:X}")
        return fmt.unpack_from(self.data, offset)


class IDMapParser:
    def __init__(self, data: bytes, path: str = ""):
        self.data = data
        self.reader = BinaryReader(data)
        self.path = path
        self.result = MappingFile(path=path, file_size=len(data), format_name="Unknown")
        self._string_cache: dict[int, str] = {}

    def parse(self) -> MappingFile:
        if not self.data:
            self.result.issues.append(ParseIssue("error", "File is empty."))
            return self.result

        if self.data[0] == FILE_MAGIC:
            self.result.format_name = "Modern .idmap"
            self._parse_modern()
        else:
            self.result.format_name = "Legacy identifier stream"
            self._parse_legacy()

        return self.result

    def _issue(self, severity: str, message: str) -> None:
        self.result.issues.append(ParseIssue(severity, message))

    def _parse_modern(self) -> None:
        if not self.reader.can_read(0, HEADER.size):
            self._issue("error", f"File is too small for modern header ({HEADER.size} bytes).")
            return

        self.result.header = HeaderInfo(*self.reader.unpack(HEADER, 0))
        header = self.result.header

        if header.magic != FILE_MAGIC:
            self._issue("error", f"Bad magic 0x{header.magic:02X}; expected 0x{FILE_MAGIC:02X}.")
        if header.version < 1:
            self._issue("error", f"Unsupported version {header.version}.")
        if header.version > 2:
            self._issue("warning", f"Version {header.version} is newer than the parser knows.")
        if not self.reader.can_read(header.string_data_offset, header.string_data_size_bytes):
            self._issue("error", "String pool is outside the file.")
            return

        self._parse_string_pool(header)
        self.result.enums = self._parse_enums(header)
        self.result.structs = self._parse_structs(header)
        vtable_data_offset = header.vtable_data_offset
        exec_function_data_offset = header.exec_function_data_offset
        vtable_table_size = header.num_vtables * NAMED_VTABLE.size
        exec_func_struct = EXEC_FUNC
        exec_table_size = header.num_exec_functions * exec_func_struct.size
        if (
            header.num_exec_functions > 0
            and not self.reader.can_read(exec_function_data_offset, exec_table_size)
            and self.reader.can_read(exec_function_data_offset, header.num_exec_functions * EXEC_FUNC_LEGACY.size)
        ):
            self._issue(
                "warning",
                "Exec function rows use the legacy 4-field layout without UnmangledName.",
            )
            exec_func_struct = EXEC_FUNC_LEGACY
            exec_table_size = header.num_exec_functions * exec_func_struct.size

        if (
            header.num_vtables > 0
            and not self.reader.can_read(exec_function_data_offset, exec_table_size)
            and self.reader.can_read(vtable_data_offset, exec_table_size)
            and exec_function_data_offset == vtable_data_offset + vtable_table_size
        ):
            self._issue(
                "warning",
                "Header reserves a VTable section, but the file appears to omit it. "
                "Parsing exec functions from VTableDataOffset as a compatibility fallback.",
            )
            exec_function_data_offset = vtable_data_offset
            vtable_data_offset = 0

        self.result.exec_functions = self._parse_fixed_table(
            exec_function_data_offset,
            header.num_exec_functions,
            exec_func_struct,
            self._make_exec_func,
            "exec function",
        )
        self.result.global_symbols = self._parse_fixed_table(
            header.global_symbol_data_offset,
            header.num_global_symbols,
            NAMED_VARIABLE,
            self._make_global_symbol,
            "global symbol",
        )
        self.result.vtables = self._parse_fixed_table(
            vtable_data_offset,
            0 if vtable_data_offset == 0 and header.num_vtables > 0 else header.num_vtables,
            NAMED_VTABLE,
            self._make_vtable,
            "vtable",
        )

    def _parse_legacy(self) -> None:
        offset = 0
        index = 0
        while offset < len(self.data):
            start = offset
            if not self.reader.can_read(offset, LEGACY_RECORD_PREFIX.size):
                self._issue("warning", f"Trailing {len(self.data) - offset} byte(s) after legacy records.")
                break
            rel_offset, name_len = self.reader.unpack(LEGACY_RECORD_PREFIX, offset)
            offset += LEGACY_RECORD_PREFIX.size
            if not self.reader.can_read(offset, name_len):
                self._issue("error", f"Legacy record {index} name overruns file.")
                break
            raw_name = self.data[offset : offset + name_len]
            offset += name_len
            self.result.legacy_records.append(
                LegacyRecord(index, start, rel_offset, raw_name.decode("utf-8", errors="replace"))
            )
            index += 1

    def _parse_string_pool(self, header: HeaderInfo) -> None:
        pool_start = header.string_data_offset
        pool_end = pool_start + header.string_data_size_bytes
        offset = pool_start
        index = 0
        while offset < pool_end:
            pool_offset = offset - pool_start
            if not self.reader.can_read(offset, STRING_LENGTH.size):
                self._issue("warning", f"String pool has truncated length field at pool offset 0x{pool_offset:X}.")
                break
            (length,) = self.reader.unpack(STRING_LENGTH, offset)
            offset += STRING_LENGTH.size
            if offset + length > pool_end:
                self._issue("warning", f"String at pool offset 0x{pool_offset:X} overruns string pool.")
                break
            value = self.data[offset : offset + length].decode("utf-8", errors="replace")
            self.result.strings.append(StringEntry(index, pool_offset, pool_start + pool_offset, length, value))
            self._string_cache[pool_offset] = value
            offset += length
            index += 1

    def _string_at(self, string_offset: int) -> str:
        if string_offset == INVALID_STRING_OFFSET:
            return ""
        if string_offset in self._string_cache:
            return self._string_cache[string_offset]

        header = self.result.header
        if not header:
            return ""
        if string_offset > header.string_data_size_bytes:
            return ""

        absolute = header.string_data_offset + string_offset
        if not self.reader.can_read(absolute, STRING_LENGTH.size):
            return ""
        (length,) = self.reader.unpack(STRING_LENGTH, absolute)
        string_start = absolute + STRING_LENGTH.size
        if string_offset + STRING_LENGTH.size + length > header.string_data_size_bytes:
            return ""
        if not self.reader.can_read(string_start, length):
            return ""
        value = self.data[string_start : string_start + length].decode("utf-8", errors="replace")
        self._string_cache[string_offset] = value
        return value

    def _parse_structs(self, header: HeaderInfo) -> list[StructInfo]:
        structs: list[StructInfo] = []
        offset = header.struct_data_offset
        for index in range(header.num_structs):
            start = offset
            if not self.reader.can_read(offset, STRUCT_PREFIX.size):
                self._issue("error", f"Struct {index} prefix is outside the file.")
                break
            name_off, super_off, size, alignment, num_members = self.reader.unpack(STRUCT_PREFIX, offset)
            offset += STRUCT_PREFIX.size
            if num_members < 0:
                self._issue("error", f"Struct {index} has negative member count {num_members}.")
                break

            members: list[MemberInfo] = []
            for member_index in range(num_members):
                if not self.reader.can_read(offset, MEMBER.size):
                    self._issue("error", f"Struct {index} member {member_index} is outside the file.")
                    break
                type_off, member_name_off, member_offset, member_size, array_dim, is_pointer, bit_count = self.reader.unpack(MEMBER, offset)
                offset += MEMBER.size
                members.append(
                    MemberInfo(
                        member_index,
                        type_off,
                        self._string_at(type_off),
                        member_name_off,
                        self._string_at(member_name_off),
                        member_offset,
                        member_size,
                        array_dim,
                        is_pointer,
                        bit_count,
                    )
                )
            structs.append(
                StructInfo(
                    index,
                    start,
                    name_off,
                    self._string_at(name_off),
                    super_off,
                    self._string_at(super_off),
                    size,
                    alignment,
                    num_members,
                    offset,
                    members,
                )
            )
        return structs

    def _parse_enums(self, header: HeaderInfo) -> list[EnumInfo]:
        enums: list[EnumInfo] = []
        offset = header.enum_data_offset
        for index in range(header.num_enums):
            start = offset
            if not self.reader.can_read(offset, ENUM_PREFIX.size):
                self._issue("error", f"Enum {index} prefix is outside the file.")
                break
            name_off, underlying_size, num_values = self.reader.unpack(ENUM_PREFIX, offset)
            offset += ENUM_PREFIX.size
            if num_values < 0:
                self._issue("error", f"Enum {index} has negative value count {num_values}.")
                break

            values: list[EnumValueInfo] = []
            for value_index in range(num_values):
                if not self.reader.can_read(offset, ENUM_VALUE.size):
                    self._issue("error", f"Enum {index} value {value_index} is outside the file.")
                    break
                value_name_off, value = self.reader.unpack(ENUM_VALUE, offset)
                offset += ENUM_VALUE.size
                values.append(EnumValueInfo(value_index, value_name_off, self._string_at(value_name_off), value))
            enums.append(EnumInfo(index, start, name_off, self._string_at(name_off), underlying_size, num_values, offset, values))
        return enums

    def _parse_fixed_table(
        self,
        table_offset: int,
        count: int,
        row_struct: struct.Struct,
        factory: Any,
        label: str,
    ) -> list[Any]:
        rows: list[Any] = []
        for index in range(count):
            offset = table_offset + index * row_struct.size
            if not self.reader.can_read(offset, row_struct.size):
                self._issue("error", f"{label.title()} {index} is outside the file.")
                break
            rows.append(factory(index, offset, row_struct.unpack_from(self.data, offset)))
        return rows

    def _make_exec_func(self, index: int, file_offset: int, fields: tuple[int, ...]) -> ExecFuncInfo:
        if len(fields) == 5:
            name_off, unmangled_name_off, rel_offset, cpp_sig_off, fallback_sig_off = fields
        else:
            name_off, rel_offset, cpp_sig_off, fallback_sig_off = fields
            unmangled_name_off = INVALID_STRING_OFFSET
        return ExecFuncInfo(
            index,
            file_offset,
            name_off,
            self._string_at(name_off),
            unmangled_name_off,
            self._string_at(unmangled_name_off),
            rel_offset,
            cpp_sig_off,
            self._string_at(cpp_sig_off),
            fallback_sig_off,
            self._string_at(fallback_sig_off),
        )

    def _make_global_symbol(self, index: int, file_offset: int, fields: tuple[int, ...]) -> NamedVariableInfo:
        variable_offset, type_off, name_off = fields
        return NamedVariableInfo(index, file_offset, variable_offset, type_off, self._string_at(type_off), name_off, self._string_at(name_off))

    def _make_vtable(self, index: int, file_offset: int, fields: tuple[int, ...]) -> NamedVTableInfo:
        vtable_offset, super_vtable_offset, name_off = fields
        return NamedVTableInfo(index, file_offset, vtable_offset, super_vtable_offset, name_off, self._string_at(name_off))


class SortableTree(ttk.Treeview):
    def __init__(self, master: tk.Widget, columns: Iterable[str], **kwargs: Any):
        super().__init__(master, columns=list(columns), show="headings", **kwargs)
        self._sort_state: dict[str, bool] = {}
        for col in self["columns"]:
            self.heading(col, text=col, command=lambda c=col: self.sort_by(c))
            self.column(col, width=120, anchor=tk.W)

    def sort_by(self, column: str) -> None:
        descending = self._sort_state.get(column, False)
        rows = [(self.set(item, column), item) for item in self.get_children("")]

        def key(row: tuple[str, str]) -> Any:
            value = row[0]
            try:
                return int(value, 0)
            except ValueError:
                return value.casefold()

        rows.sort(key=key, reverse=descending)
        for index, (_, item) in enumerate(rows):
            self.move(item, "", index)
        self._sort_state[column] = not descending


class IDMapVisualizer(tk.Tk):
    def __init__(self, initial_path: str | None = None):
        super().__init__()
        self.title("IDA Mappings Visualizer")
        self.geometry("1280x780")
        self.minsize(980, 620)

        self.mapping: MappingFile | None = None
        self.current_rows: dict[str, list[dict[str, Any]]] = {}
        self.trees: dict[str, SortableTree] = {}
        self.filters: dict[str, tk.StringVar] = {}

        self._build_menu()
        self._build_layout()
        if initial_path:
            self.load_file(initial_path)

    def _build_menu(self) -> None:
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Open...", accelerator="Ctrl+O", command=self.open_file)
        file_menu.add_command(label="Export Current Tab CSV...", command=self.export_current_tab_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menu.add_cascade(label="File", menu=file_menu)
        self.config(menu=menu)
        self.bind("<Control-o>", lambda _event: self.open_file())

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=8)
        root.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(root)
        top.pack(fill=tk.X)
        ttk.Button(top, text="Open .idmap", command=self.open_file).pack(side=tk.LEFT)
        self.path_var = tk.StringVar(value="No file loaded")
        ttk.Label(top, textvariable=self.path_var).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        paned = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=5)
        paned.add(right, weight=2)

        self.notebook = ttk.Notebook(left)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.detail_text = tk.Text(right, wrap=tk.NONE, height=12)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.detail_text.configure(state=tk.DISABLED)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(root, textvariable=self.status_var, anchor=tk.W).pack(fill=tk.X, pady=(6, 0))

        self._add_table_tab("Summary", ("Field", "Value"), searchable=False)
        self._add_table_tab("Issues", ("Severity", "Message"), searchable=True)
        self._add_table_tab("Structs", ("Index", "Offset", "Name", "Super", "Size", "Align", "Members"), searchable=True)
        self._add_table_tab("Members", ("Struct", "Index", "Offset", "Name", "Type", "Size", "Array", "Ptr", "Bitfield"), searchable=True)
        self._add_table_tab("Enums", ("Index", "Offset", "Name", "Underlying", "Values"), searchable=True)
        self._add_table_tab("Enum Values", ("Enum", "Index", "Name", "Value"), searchable=True)
        self._add_table_tab("Exec Functions", ("Index", "Offset", "RVA", "Name", "Unmangled Name", "Cpp Signature", "Fallback Signature"), searchable=True)
        self._add_table_tab("Globals", ("Index", "Offset", "RVA", "Name", "Type"), searchable=True)
        self._add_table_tab("VTables", ("Index", "Offset", "RVA", "Super RVA", "Name"), searchable=True)
        self._add_table_tab("Strings", ("Index", "Pool Offset", "Absolute", "Length", "Value"), searchable=True)
        self._add_table_tab("Legacy", ("Index", "Offset", "RVA", "Name"), searchable=True)
        self._add_table_tab("Header", ("Field", "Value"), searchable=False)

    def _add_table_tab(self, name: str, columns: Iterable[str], searchable: bool) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=name)

        if searchable:
            filter_bar = ttk.Frame(tab)
            filter_bar.pack(fill=tk.X, pady=(0, 4))
            ttk.Label(filter_bar, text="Filter").pack(side=tk.LEFT)
            var = tk.StringVar()
            var.trace_add("write", lambda *_args, tab_name=name: self.refresh_tree(tab_name))
            self.filters[name] = var
            ttk.Entry(filter_bar, textvariable=var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        frame = ttk.Frame(tab)
        frame.pack(fill=tk.BOTH, expand=True)
        tree = SortableTree(frame, columns)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        xscroll = ttk.Scrollbar(tab, orient=tk.HORIZONTAL, command=tree.xview)
        xscroll.pack(fill=tk.X)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.bind("<<TreeviewSelect>>", lambda _event, tab_name=name: self.show_selection_detail(tab_name))
        self.trees[name] = tree
        self.current_rows[name] = []

    def open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open IDA mappings file",
            filetypes=(("IDA mappings", "*.idmap *.usmap"), ("All files", "*.*")),
        )
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> None:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
            self.mapping = IDMapParser(data, path).parse()
        except Exception as exc:
            messagebox.showerror("Load failed", str(exc))
            return

        self.path_var.set(path)
        self.populate_all()
        issue_text = f", {len(self.mapping.issues)} issue(s)" if self.mapping.issues else ""
        self.status_var.set(f"Loaded {os.path.basename(path)} ({self.mapping.format_name}{issue_text})")

    def populate_all(self) -> None:
        if not self.mapping:
            return
        m = self.mapping
        self.set_rows("Summary", [{"Field": key, "Value": value} for key, value in m.summary_rows()])
        self.set_rows("Issues", [{"Severity": i.severity, "Message": i.message} for i in m.issues])
        self.set_rows("Header", self._header_rows(m.header))
        self.set_rows("Structs", [self._struct_row(s) for s in m.structs])
        self.set_rows("Members", [self._member_row(s, mem) for s in m.structs for mem in s.members])
        self.set_rows("Enums", [self._enum_row(e) for e in m.enums])
        self.set_rows("Enum Values", [self._enum_value_row(e, value) for e in m.enums for value in e.values])
        self.set_rows("Exec Functions", [self._exec_row(f) for f in m.exec_functions])
        self.set_rows("Globals", [self._global_row(g) for g in m.global_symbols])
        self.set_rows("VTables", [self._vtable_row(v) for v in m.vtables])
        self.set_rows("Strings", [self._string_row(s) for s in m.strings])
        self.set_rows("Legacy", [self._legacy_row(r) for r in m.legacy_records])

    def set_rows(self, tab_name: str, rows: list[dict[str, Any]]) -> None:
        self.current_rows[tab_name] = rows
        self.refresh_tree(tab_name)

    def refresh_tree(self, tab_name: str) -> None:
        tree = self.trees[tab_name]
        for item in tree.get_children(""):
            tree.delete(item)

        needle = self.filters.get(tab_name, tk.StringVar(value="")).get().casefold()
        columns = list(tree["columns"])
        for row in self.current_rows.get(tab_name, []):
            values = [self._format_value(row.get(col, "")) for col in columns]
            if needle and needle not in " ".join(values).casefold():
                continue
            tree.insert("", tk.END, values=values)

        self._autosize_columns(tree)

    def show_selection_detail(self, tab_name: str) -> None:
        tree = self.trees[tab_name]
        selected = tree.selection()
        if not selected:
            return
        values = tree.item(selected[0], "values")
        detail = "\n".join(f"{column}: {value}" for column, value in zip(tree["columns"], values))
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, detail)
        self.detail_text.configure(state=tk.DISABLED)

    def export_current_tab_csv(self) -> None:
        tab_name = self.notebook.tab(self.notebook.select(), "text")
        rows = self.current_rows.get(tab_name, [])
        if not rows:
            messagebox.showinfo("Nothing to export", f"The {tab_name} tab has no rows.")
            return
        path = filedialog.asksaveasfilename(
            title=f"Export {tab_name}",
            defaultextension=".csv",
            filetypes=(("CSV", "*.csv"), ("All files", "*.*")),
        )
        if not path:
            return
        columns = list(self.trees[tab_name]["columns"])
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({col: row.get(col, "") for col in columns})
        self.status_var.set(f"Exported {tab_name} to {path}")

    @staticmethod
    def _autosize_columns(tree: SortableTree) -> None:
        for col in tree["columns"]:
            width = max(80, min(520, len(col) * 9 + 22))
            for item in tree.get_children("")[:80]:
                width = max(width, min(520, len(str(tree.set(item, col))) * 8 + 22))
            tree.column(col, width=width)

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, bool):
            return "yes" if value else "no"
        return str(value)

    @staticmethod
    def _hex(value: int) -> str:
        return f"0x{value:X}"

    def _header_rows(self, header: HeaderInfo | None) -> list[dict[str, str]]:
        if not header:
            return []
        rows: list[dict[str, str]] = []
        for key, value in asdict(header).items():
            display = self._hex(value) if key.endswith("offset") or key == "magic" else str(value)
            rows.append({"Field": key, "Value": display})
        return rows

    def _struct_row(self, s: StructInfo) -> dict[str, Any]:
        return {
            "Index": s.index,
            "Offset": self._hex(s.file_offset),
            "Name": s.name,
            "Super": s.super_name,
            "Size": self._hex(s.size),
            "Align": s.alignment,
            "Members": s.num_members,
        }

    def _member_row(self, s: StructInfo, m: MemberInfo) -> dict[str, Any]:
        bitfield = "" if m.bitfield_bit_count == 0xFF else str(m.bitfield_bit_count)
        return {
            "Struct": s.name,
            "Index": m.index,
            "Offset": self._hex(m.offset),
            "Name": m.name,
            "Type": m.type,
            "Size": m.size,
            "Array": m.array_dim,
            "Ptr": m.is_pointer,
            "Bitfield": bitfield,
        }

    def _enum_row(self, e: EnumInfo) -> dict[str, Any]:
        return {
            "Index": e.index,
            "Offset": self._hex(e.file_offset),
            "Name": e.name,
            "Underlying": e.underlying_type_size_bytes,
            "Values": e.num_values,
        }

    def _enum_value_row(self, e: EnumInfo, v: EnumValueInfo) -> dict[str, Any]:
        return {"Enum": e.name, "Index": v.index, "Name": v.name, "Value": v.value}

    def _exec_row(self, f: ExecFuncInfo) -> dict[str, Any]:
        return {
            "Index": f.index,
            "Offset": self._hex(f.file_offset),
            "RVA": self._hex(f.offset_relative_to_imagebase),
            "Name": f.mangled_name,
            "Unmangled Name": f.unmangled_name,
            "Cpp Signature": f.cpp_type_signature,
            "Fallback Signature": f.fallback_cpp_signature_info,
        }

    def _global_row(self, g: NamedVariableInfo) -> dict[str, Any]:
        return {
            "Index": g.index,
            "Offset": self._hex(g.file_offset),
            "RVA": self._hex(g.variable_offset),
            "Name": g.name,
            "Type": g.type,
        }

    def _vtable_row(self, v: NamedVTableInfo) -> dict[str, Any]:
        return {
            "Index": v.index,
            "Offset": self._hex(v.file_offset),
            "RVA": self._hex(v.vtable_offset),
            "Super RVA": self._hex(v.super_vtable_offset),
            "Name": v.name,
        }

    def _string_row(self, s: StringEntry) -> dict[str, Any]:
        return {
            "Index": s.index,
            "Pool Offset": self._hex(s.pool_offset),
            "Absolute": self._hex(s.absolute_offset),
            "Length": s.length,
            "Value": s.value,
        }

    def _legacy_row(self, r: LegacyRecord) -> dict[str, Any]:
        return {
            "Index": r.index,
            "Offset": self._hex(r.file_offset),
            "RVA": self._hex(r.offset_relative_to_imagebase),
            "Name": r.name,
        }


def mapping_to_jsonable(mapping: MappingFile) -> dict[str, Any]:
    return asdict(mapping)


def load_mapping(path: str) -> MappingFile:
    with open(path, "rb") as handle:
        return IDMapParser(handle.read(), path).parse()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Visualize IDAExecFunctionsImporter .idmap files.")
    parser.add_argument("path", nargs="?", help="Path to a .idmap file")
    parser.add_argument("--dump-json", action="store_true", help="Print parsed content as JSON instead of opening the GUI")
    args = parser.parse_args(argv)

    if args.dump_json:
        if not args.path:
            parser.error("--dump-json requires a path")
        print(json.dumps(mapping_to_jsonable(load_mapping(args.path)), indent=2))
        return 0

    app = IDMapVisualizer(args.path)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
